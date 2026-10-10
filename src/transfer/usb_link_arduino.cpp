// ============================================================================
// USB link transports on the Arduino ESP32 core (task2 items 2 and 3).
//
//   * Serial  - the core's standard `Serial` object, whatever Tools > USB
//               routed it to: the TinyUSB CDC port ("USB-OTG" + "CDC On
//               Boot"), the hardware USB-Serial/JTAG port ("Hardware CDC and
//               JTAG") or UART0 (CDC On Boot disabled). Frames are COBS +
//               CRC32 (link.h), so the sketch builds and the link works with
//               ANY USB setting.
//   * HID     - a vendor-usage-page HID interface (0xFF00, 64-byte reports,
//               Trezor style) that exists only when the core links TinyUSB
//               (USB Mode = USB-OTG). Without TinyUSB the transport is simply
//               reported absent; nothing else changes.
//
// Both transports feed the same protocol core (link.c) and the same
// inbox/outbox, so from the wallet's point of view they are one channel
// (MW_CHANNEL_USB_LINK).
//
// Debug output (task2 item 3): the link task drains the log ring of
// src/hal/log.h and forwards every line as an MW_LINK_EVT_LOG frame to each
// transport that has talked to the host recently. Because the lines are
// framed like every other message they cannot corrupt the protocol on the
// serial port, and the host program shows them in its console.
//
// USB.begin() ordering: with "CDC On Boot" the core starts USB before
// setup(); the HID interface is still picked up because the USBHID/HID device
// objects below are globals whose constructors register the interface during
// static initialisation, i.e. before app_main(). Without "CDC On Boot" the
// sketch has to start USB itself, which mw_usb_link_init() does.
//
// NOTE: like the rest of the device layer this file has not been compiled in
// this workspace (no ESP32 core here). Core API relied upon: Stream-style
// Serial (available/read/write), USBHID (addDevice/begin/ready/SendReport),
// USBHIDDevice (_onGetDescriptor/_onOutput), ESPUSB (VID/PID/begin).
//
// SPDX-License-Identifier: MIT
// ============================================================================
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>

#include "transfer.h"
#include "link.h"
#include "usb_descriptors.h"
#include "../config/app_config.h"
#include "../hal/hal.h"
#include "../hal/log.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <esp_heap_caps.h>

#include <string.h>
#include <stdlib.h>

extern "C" {
mw_err_t mw_usb_link_init(void);
void     mw_usb_link_stop(void);
bool     mw_usb_link_running(void);
}

// app_config.h: MW_USE_HID / MW_USE_SERIAL leave a transport out entirely.
#if defined(MW_USB_TINYUSB) && MW_USE_HID
#  include <USB.h>
#  include <USBHID.h>
#  define MW_LINK_HAVE_HID 1
#else
#  define MW_LINK_HAVE_HID 0
#endif
#if MW_USE_HID && !defined(MW_USB_TINYUSB) && !MW_USE_SERIAL
#  warning "MW_USE_HID needs USB Mode = USB-OTG (TinyUSB); with MW_USE_SERIAL 0 the device has no USB link"
#endif
#define MW_LINK_HAVE_SERIAL (MW_USE_SERIAL ? 1 : 0)

// `Serial` is UART0 when the IDE routes the USB CDC nowhere; then the
// protocol owns UART0 and hal_esp32.cpp installs no UART console.
#define MW_LINK_SERIAL Serial

namespace {

// How long after the last request a transport keeps receiving log events.
constexpr uint32_t HOST_ACTIVE_MS   = 30000;
constexpr uint32_t SEND_DEADLINE_MS = 5000;   // responses
constexpr uint32_t LOG_DEADLINE_MS  = 100;    // log events: never stall the link task
constexpr uint32_t DIAG_PERIOD_MS   = 1000;   // receive-error counters, at most this often

// ---------------------------------------------------------------------------
// HID: report descriptor, device and the OUT-report ring
// ---------------------------------------------------------------------------
#if MW_LINK_HAVE_HID

// Vendor-defined usage page 0xFF00, usage 1; one 63-byte input and one 63-byte
// output report with report ID MW_LINK_HID_REPORT_ID. 1 + 63 = 64 bytes on the
// wire, one full-speed packet.
const uint8_t HID_REPORT_DESC[] = {
    0x06, 0x00, 0xFF,               // Usage Page (Vendor 0xFF00)
    0x09, 0x01,                     // Usage (1)
    0xA1, 0x01,                     // Collection (Application)
    0x85, MW_LINK_HID_REPORT_ID,    //   Report ID
    0x09, 0x02,                     //   Usage (2)  - device -> host
    0x15, 0x00,                     //   Logical Minimum (0)
    0x26, 0xFF, 0x00,               //   Logical Maximum (255)
    0x75, 0x08,                     //   Report Size (8)
    0x95, MW_LINK_HID_DATA,         //   Report Count (63)
    0x81, 0x02,                     //   Input (Data, Var, Abs)
    0x09, 0x03,                     //   Usage (3)  - host -> device
    0x15, 0x00,                     //   Logical Minimum (0)
    0x26, 0xFF, 0x00,               //   Logical Maximum (255)
    0x75, 0x08,                     //   Report Size (8)
    0x95, MW_LINK_HID_DATA,         //   Report Count (63)
    0x91, 0x02,                     //   Output (Data, Var, Abs)
    0xC0                            // End Collection
};

// 128 x 63 B = ~8 KB of internal RAM: room for a burst of a large PUT while
// the link task is busy sending a response or a log line.
constexpr size_t HID_RING_SLOTS = 128;
struct HidRing {
    uint8_t  slot[HID_RING_SLOTS][MW_LINK_HID_DATA];
    volatile uint32_t head;
    volatile uint32_t tail;
    uint32_t overruns;
};
HidRing      g_ring;
portMUX_TYPE g_ring_mux = portMUX_INITIALIZER_UNLOCKED;

bool ring_push(const uint8_t* data, size_t n) {
    bool ok = false;
    portENTER_CRITICAL(&g_ring_mux);
    uint32_t next = (g_ring.head + 1) % HID_RING_SLOTS;
    if (next != g_ring.tail) {
        memset(g_ring.slot[g_ring.head], 0, MW_LINK_HID_DATA);
        memcpy(g_ring.slot[g_ring.head], data, n < MW_LINK_HID_DATA ? n : MW_LINK_HID_DATA);
        g_ring.head = next;
        ok = true;
    } else {
        g_ring.overruns++;
    }
    portEXIT_CRITICAL(&g_ring_mux);
    return ok;
}

bool ring_pop(uint8_t out[MW_LINK_HID_DATA]) {
    bool ok = false;
    portENTER_CRITICAL(&g_ring_mux);
    if (g_ring.tail != g_ring.head) {
        memcpy(out, g_ring.slot[g_ring.tail], MW_LINK_HID_DATA);
        g_ring.tail = (g_ring.tail + 1) % HID_RING_SLOTS;
        ok = true;
    }
    portEXIT_CRITICAL(&g_ring_mux);
    return ok;
}

USBHID g_hid;

class MwHidLink : public USBHIDDevice {
public:
    MwHidLink() { g_hid.addDevice(this, sizeof(HID_REPORT_DESC)); }

    uint16_t _onGetDescriptor(uint8_t* dst) override {
        memcpy(dst, HID_REPORT_DESC, sizeof(HID_REPORT_DESC));
        return sizeof(HID_REPORT_DESC);
    }

    // Runs on the TinyUSB task. Depending on the core version the report ID
    // has either been stripped (len == 63) or is still the first byte
    // (len == 64); accept both.
    void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t len) override {
        (void)report_id;
        if (!buffer || len == 0) return;
        if (len > MW_LINK_HID_DATA && buffer[0] == MW_LINK_HID_REPORT_ID) {
            buffer++;
            len--;
        }
        ring_push(buffer, len);
    }
};

MwHidLink g_hid_dev;

#endif  // MW_LINK_HAVE_HID

// ---------------------------------------------------------------------------
// Link task state
// ---------------------------------------------------------------------------
struct Link {
    bool         running;
    TaskHandle_t task;
    SemaphoreHandle_t mutex;

    mw_link_rx_t rx_serial;
    mw_link_rx_t rx_hid;
    uint8_t*     rx_serial_buf;      // COBS-encoded frame, decoded in place
    uint8_t*     rx_hid_buf;         // raw message
    uint8_t*     tx_msg;             // response / event message
    uint8_t*     tx_frame;           // COBS-encoded response (serial only)
    size_t       rx_serial_cap, rx_hid_cap, tx_msg_cap, tx_frame_cap;

    uint32_t     last_serial_rx_ms;  // 0 = never / host gone
    uint32_t     last_hid_rx_ms;

    uint32_t     diag_ms;            // last receive-error report
    uint32_t     diag_overruns, diag_hid_dropped, diag_ser_dropped;
};

Link g_link;

void* psram_alloc(size_t n) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n);
    return p;
}

void psram_free(void* p, size_t n) {
    (void)n;
    free(p);
}

void port_lock(void* ctx)   { xSemaphoreTake((SemaphoreHandle_t)ctx, portMAX_DELAY); }
void port_unlock(void* ctx) { xSemaphoreGive((SemaphoreHandle_t)ctx); }

bool buffers_alloc() {
    g_link.rx_serial_cap = mw_cobs_max_encoded(MW_LINK_MAX_MSG);
    g_link.rx_hid_cap    = MW_LINK_MAX_MSG;
    g_link.tx_msg_cap    = MW_LINK_MAX_MSG;
    g_link.tx_frame_cap  = mw_cobs_max_encoded(MW_LINK_MAX_MSG) + 1;

    g_link.rx_serial_buf = (uint8_t*)psram_alloc(g_link.rx_serial_cap);
    g_link.rx_hid_buf    = (uint8_t*)psram_alloc(g_link.rx_hid_cap);
    g_link.tx_msg        = (uint8_t*)psram_alloc(g_link.tx_msg_cap);
    g_link.tx_frame      = (uint8_t*)psram_alloc(g_link.tx_frame_cap);
    return g_link.rx_serial_buf && g_link.rx_hid_buf && g_link.tx_msg && g_link.tx_frame;
}

void buffers_free() {
    free(g_link.rx_serial_buf); g_link.rx_serial_buf = nullptr;
    free(g_link.rx_hid_buf);    g_link.rx_hid_buf = nullptr;
    free(g_link.tx_msg);        g_link.tx_msg = nullptr;
    free(g_link.tx_frame);      g_link.tx_frame = nullptr;
}

bool host_active(uint32_t last_rx_ms) {
    return last_rx_ms != 0 && (millis() - last_rx_ms) < HOST_ACTIVE_MS;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------
// The serial host counts as gone when the port is closed (no DTR on a USB
// CDC port) or the core refuses bytes: log forwarding to it stops at once
// instead of stalling the link task for every line, and HID keeps working.
void serial_host_gone() { g_link.last_serial_rx_ms = 0; }

bool send_serial(const uint8_t* msg, size_t len, uint32_t deadline_ms) {
#if !MW_LINK_HAVE_SERIAL
    (void)msg; (void)len; (void)deadline_ms;
    return false;                        // built without the serial transport
#else
    if (!MW_LINK_SERIAL) { serial_host_gone(); return false; }
    size_t n = mw_link_serial_frame(msg, len, g_link.tx_frame, g_link.tx_frame_cap);
    if (n == 0) return false;
    const uint32_t t0 = millis();
    size_t done = 0;
    while (done < n) {
        size_t w = MW_LINK_SERIAL.write(g_link.tx_frame + done, n - done);
        if (w == 0) { serial_host_gone(); return false; }
        done += w;
        if (done >= n) break;
        if (millis() - t0 > deadline_ms) {
            if (deadline_ms >= SEND_DEADLINE_MS)
                MW_LOGE("link", "serial tx stalled after %u/%u bytes", (unsigned)done, (unsigned)n);
            serial_host_gone();
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    MW_LINK_SERIAL.flush();
    return true;
#endif
}

#if MW_LINK_HAVE_HID
bool send_hid(const uint8_t* msg, size_t len, uint32_t deadline_ms) {
    const size_t reports = mw_link_hid_report_count(len);
    uint8_t rep[MW_LINK_HID_DATA];
    const uint32_t t0 = millis();
    for (size_t i = 0; i < reports; ++i) {
        mw_link_hid_report(msg, len, i, rep);
        while (!g_hid.SendReport(MW_LINK_HID_REPORT_ID, rep, MW_LINK_HID_DATA,
                                 deadline_ms < 250 ? deadline_ms : 250)) {
            if (millis() - t0 > deadline_ms) {
                if (deadline_ms >= SEND_DEADLINE_MS)
                    MW_LOGE("link", "hid tx stalled at report %u/%u", (unsigned)i, (unsigned)reports);
                else
                    g_link.last_hid_rx_ms = 0;     // nobody reads the log: stop sending it
                return false;
            }
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }
    return true;
}
#endif

void dispatch(mw_link_rx_t* rx, bool via_hid) {
    size_t n = mw_link_handle(rx->buf, rx->len, g_link.tx_msg, g_link.tx_msg_cap);
    mw_link_rx_reset(rx);
    if (n == 0) return;
    MW_LOGD("link", "%s -> %s (%u bytes)", via_hid ? "hid" : "serial",
            mw_link_cmd_name(g_link.tx_msg[9]), (unsigned)n);   // header: cmd at 9
#if MW_LINK_HAVE_HID
    if (via_hid) { send_hid(g_link.tx_msg, n, SEND_DEADLINE_MS); return; }
#else
    (void)via_hid;
#endif
    send_serial(g_link.tx_msg, n, SEND_DEADLINE_MS);
}

#if MW_LINK_HAVE_HID
// Feeds every queued OUT report to the receiver and answers complete
// requests. Called by the task loop and between log lines, so log forwarding
// never lets the ring overflow during a PUT.
bool pump_hid() {
    uint8_t rep[MW_LINK_HID_DATA];
    bool any = false;
    while (ring_pop(rep)) {
        any = true;
        size_t used = 0;
        if (mw_link_rx_feed(&g_link.rx_hid, rep, MW_LINK_HID_DATA, &used)) {
            g_link.last_hid_rx_ms = millis() ? millis() : 1;
            dispatch(&g_link.rx_hid, true);
        }
    }
    return any;
}
#endif

// Receive-error counters, reported when they change and at most once per
// DIAG_PERIOD_MS, so the report itself cannot flood a struggling link.
void report_rx_errors() {
    const uint32_t now = millis();
    if (now - g_link.diag_ms < DIAG_PERIOD_MS) return;
#if MW_LINK_HAVE_HID
    uint32_t overruns;
    portENTER_CRITICAL(&g_ring_mux);
    overruns = g_ring.overruns;
    portEXIT_CRITICAL(&g_ring_mux);
    const uint32_t hid_dropped = g_link.rx_hid.dropped;
#else
    const uint32_t overruns = 0, hid_dropped = 0;
#endif
    const uint32_t ser_dropped = g_link.rx_serial.dropped;
    if (overruns == g_link.diag_overruns && hid_dropped == g_link.diag_hid_dropped &&
        ser_dropped == g_link.diag_ser_dropped) return;
    g_link.diag_ms = now;
    MW_LOGI("link", "rx errors: hid ring overruns %u, hid frames dropped %u, serial frames dropped %u",
            (unsigned)overruns, (unsigned)hid_dropped, (unsigned)ser_dropped);
    g_link.diag_overruns = overruns;
    g_link.diag_hid_dropped = hid_dropped;
    g_link.diag_ser_dropped = ser_dropped;
}

// What the untrusted host may see (audit round 2, item 5). By default only
// PROGRESS and ERROR lines leave the device: INFO carries wallet names,
// unlock state, passphrase variant and amounts. INFO and DEBUG go out only
// in the debug mode the user turns on on the device itself. Lines from the
// password / unlock code never leave the device, whatever the mode.
bool log_line_for_host(mw_log_level_t level, const char* line) {
    static const char* const k_private_tags[] = {
        "[auth]", "[pin]", "[unlock]", "[pass", "[devauth]", "[secure"
    };
    for (const char* t : k_private_tags)
        if (strncmp(line, t, strlen(t)) == 0) return false;
    if (level == MW_LOG_PROGRESS || level == MW_LOG_ERROR) return true;
    return mw_log_debug_enabled();
}

// Forwards queued log lines to every transport with a live host. A line
// that neither transport can take is dropped: the console is a convenience,
// the ring must never back-pressure the firmware.
void forward_logs() {
    char           line[MW_LOG_LINE_MAX];
    mw_log_level_t level;
    int budget = 8;                                  // per pump, keep latency low
    while (budget-- > 0) {
        const bool ser = host_active(g_link.last_serial_rx_ms);
#if MW_LINK_HAVE_HID
        // Not while a request is arriving over HID: the host is busy sending.
        const bool hid = host_active(g_link.last_hid_rx_ms) && !g_link.rx_hid.in_frame;
#else
        const bool hid = false;
#endif
        if (!ser && !hid) return;                    // leave the lines for later
        if (!mw_log_pop(&level, line, sizeof line)) return;
        if (!log_line_for_host(level, line)) { budget++; continue; }
        size_t n = 0;
        if (mw_link_msg_build(MW_LINK_EVT_LOG, (uint8_t)level, (const uint8_t*)line,
                              (uint32_t)strlen(line), g_link.tx_msg, g_link.tx_msg_cap,
                              &n) != MW_OK) continue;
        if (ser) send_serial(g_link.tx_msg, n, LOG_DEADLINE_MS);
#if MW_LINK_HAVE_HID
        if (hid) send_hid(g_link.tx_msg, n, LOG_DEADLINE_MS);
        pump_hid();                                  // drain OUT reports between lines
#endif
    }
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------
void link_task(void* arg) {
    (void)arg;
    uint8_t chunk[256];

    while (g_link.running) {
        bool idle = true;

        // ---- serial ------------------------------------------------------
#if MW_LINK_HAVE_SERIAL
        int avail = MW_LINK_SERIAL.available();
        while (avail > 0) {
            size_t want = (size_t)avail < sizeof(chunk) ? (size_t)avail : sizeof(chunk);
            size_t got  = MW_LINK_SERIAL.readBytes(chunk, want);
            if (got == 0) break;
            idle = false;
            size_t off = 0;
            while (off < got) {
                size_t used = 0;
                bool ready = mw_link_rx_feed(&g_link.rx_serial, chunk + off, got - off, &used);
                off += used;
                if (ready) {
                    g_link.last_serial_rx_ms = millis() ? millis() : 1;
                    dispatch(&g_link.rx_serial, false);
                }
                if (used == 0) break;
            }
            avail = MW_LINK_SERIAL.available();
        }
#endif

        // ---- hid ---------------------------------------------------------
#if MW_LINK_HAVE_HID
        if (pump_hid()) idle = false;
#endif

        // ---- log events --------------------------------------------------
        forward_logs();
        report_rx_errors();

        static uint32_t s_hwm_ms = 0;
        if (mw_log_debug_enabled() && millis() - s_hwm_ms > 60000u) {
            s_hwm_ms = millis();
            MW_LOGD("link", "usblink stack min free %u B",
                    (unsigned)uxTaskGetStackHighWaterMark(nullptr));
        }

        vTaskDelay(pdMS_TO_TICKS(idle ? 5 : 1));
    }
    g_link.task = nullptr;
    vTaskDelete(nullptr);
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------
extern "C" bool mw_usb_link_running(void) { return g_link.running; }

extern "C" mw_err_t mw_usb_link_init(void) {
    if (g_link.running) return MW_OK;
#if !MW_LINK_HAVE_SERIAL && !MW_LINK_HAVE_HID
    MW_LOGI("link", "built without a USB transport (MW_USE_SERIAL / MW_USE_HID)");
    return MW_ERR_NOT_SUPPORTED;
#endif

    if (!g_link.mutex) {
        g_link.mutex = xSemaphoreCreateMutex();
        if (!g_link.mutex) return MW_ERR_MEMORY;
    }
    if (!buffers_alloc()) {
        buffers_free();
        MW_LOGE("link", "init: buffer allocation failed");
        return MW_ERR_MEMORY;
    }

    mw_link_port_t port;
    port.lock   = port_lock;
    port.unlock = port_unlock;
    port.alloc  = psram_alloc;
    port.free   = psram_free;
    port.ctx    = g_link.mutex;
    mw_link_set_port(&port);
    mw_link_init();

    mw_link_rx_init(&g_link.rx_serial, MW_LINK_TRANSPORT_SERIAL,
                    g_link.rx_serial_buf, g_link.rx_serial_cap);
    mw_link_rx_init(&g_link.rx_hid, MW_LINK_TRANSPORT_HID,
                    g_link.rx_hid_buf, g_link.rx_hid_cap);

    // The standard Serial. begin() is harmless when the core already opened
    // it (CDC On Boot); on UART0 it sets the baud rate the host must use.
    uint8_t caps = 0;
#if MW_LINK_HAVE_SERIAL
    MW_LINK_SERIAL.begin(115200);
    MW_LINK_SERIAL.setTimeout(5);
    caps |= MW_LINK_CAP_SERIAL;
#endif
#if MW_LINK_HAVE_HID
    memset(&g_ring, 0, sizeof(g_ring));
    g_hid.begin();
    caps |= MW_LINK_CAP_HID;
#  if !(defined(ARDUINO_USB_CDC_ON_BOOT) && (ARDUINO_USB_CDC_ON_BOOT == 1))
    // Nobody started USB yet: set the identity and start it here. With CDC On
    // Boot the core has already done so and the calls below are no-ops.
    USB.VID(MW_USB_VID);
    USB.PID(MW_USB_PID_LINK);
    USB.manufacturerName("Monero");
    USB.productName("Cold Wallet");
#  endif
    USB.begin();
#endif

    g_link.running = true;
    // 8 KiB: mw_link_handle() runs on this task, with snprintf-based log
    // formatting and the dispatcher on top of the loop's own 256-byte chunk
    // and 160-byte log line (audit round 2: 6 KiB was tight). The high-water
    // mark is logged once a minute in debug mode (link_task).
    const BaseType_t ok = xTaskCreatePinnedToCore(link_task, "usblink", 8192, nullptr,
                                                  4, &g_link.task, MW_UI_TASK_CORE);
    if (ok != pdPASS) {
        g_link.running = false;
        buffers_free();
        MW_LOGE("link", "init: task creation failed");
        return MW_ERR_MEMORY;
    }

    mw_link_set_up(true, caps);
    MW_LOGI("link", "up:%s%s", (caps & MW_LINK_CAP_SERIAL) ? " serial" : "",
            (caps & MW_LINK_CAP_HID) ? " hid" : "");
    return MW_OK;
}

extern "C" void mw_usb_link_stop(void) {
    if (!g_link.running) return;
    g_link.running = false;
    for (int i = 0; i < 50 && g_link.task; ++i) vTaskDelay(pdMS_TO_TICKS(2));
    mw_link_set_up(false, 0);
    mw_link_deinit();
    buffers_free();
}

#endif  // ARDUINO && !MW_HOST_BUILD
