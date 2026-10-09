// ============================================================================
// ESP32-S3 HAL core: boot order, capabilities, power, reboot, factory reset.
//
// Boot order is not arbitrary (TZ 8.2 / 4.1):
//
//   1. TRNG                mw_random_init() calls bootloader_random_enable()
//                          and runs the SP 800-90B health tests.  It has to
//                          be first: everything that follows may allocate,
//                          and an allocator seeded from a dead entropy pool
//                          is exactly the failure this device must not have.
//   2. PSRAM               cn_slow_hash needs 2 MB contiguous (TZ 1.4).  A
//                          board that claims HAS_PSRAM and has none is a
//                          hard failure, not a degraded mode.
//   3. Display             so step 4 onwards can put something on the glass,
//                          including the touch calibration targets.
//   4. Inputs              touch and buttons; either may be absent.
//   5. SD                  last, and always optional - the card is a courier,
//                          not a boot dependency.
//
// The camera is deliberately NOT in that list.  An OV2640 draws around 30 mA
// the whole time it is streaming and holds two framebuffers in PSRAM, and it
// is only wanted on one screen (TZ 3.7 QR scanning).  The UI calls
// mw_camera_init() when it opens the scan screen and mw_camera_deinit() when
// it leaves, so a wallet that never scans a QR code never powers the sensor.
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <string.h>

#include "display_drivers.h"
#include "../crypto/random.h"

#include <esp_system.h>
#include <esp_heap_caps.h>
#include <nvs_flash.h>
#include <esp_partition.h>
#include <esp_attr.h>
#include <esp_idf_version.h>
#include <freertos/task.h>

// ===========================================================================
// Compile-time platform contract
// ===========================================================================

// TZ 1.4: the S3 is the only part with PSRAM + USB OTG + HMAC/eFuse + TRNG.
// Building for anything else would silently produce a wallet that cannot
// protect its keys, so refuse at compile time.
#if !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "Monero Cold Wallet targets ESP32-S3 only (TZ 1.4). Select an ESP32-S3 board in Tools > Board: ESP32S3 Dev Module."
#endif

// TZ 8.4: air-gapped.  The radios are never initialised, and more importantly
// the stacks are never linked in - so if any translation unit in this build
// has pulled in a networking header, the build must fail rather than ship a
// wallet with a usable radio one library call away.
#if defined(WiFi_h) || defined(_WIFI_H_) || defined(WiFiClient_h)      || \
    defined(ETH_H_)  || defined(_ETH_H_)                              || \
    defined(BluetoothSerial_h) || defined(_BLUETOOTHSERIAL_H_)        || \
    defined(_BLEDevice_H_)     || defined(_BLE_DEVICE_H_)             || \
    defined(SimpleBLE_h)       || defined(_ESP_NOW_H_) || defined(ESP_NOW_H)
#error "TZ 8.4 air-gapped build: a Wi-Fi/BT/Ethernet header was included. Remove the #include - no networking stack may be linked into this firmware."
#endif
#if defined(MW_ENABLE_WIFI) || defined(MW_ENABLE_BT)
#error "TZ 8.4 air-gapped build: MW_ENABLE_WIFI / MW_ENABLE_BT must stay undefined."
#endif

// Boards that promise PSRAM must be built with it enabled, or the promise is
// a lie that only surfaces when a 2 MB allocation fails mid-signature.
#if HAS_PSRAM && !defined(BOARD_HAS_PSRAM) && !defined(CONFIG_SPIRAM)
#warning "HAS_PSRAM is 1 but PSRAM is not enabled in the build - set Tools > PSRAM to OPI/QSPI PSRAM."
#endif

// ===========================================================================
// Diagnostics - the unified log of src/hal/log.h (task2 items 3 and 10)
// ===========================================================================
// Every line goes through mw_log_write(); this file only installs the
// platform pieces: a FreeRTOS mutex and, when it does not collide with the
// exchange protocol, a UART0 sink.
//
// Where does the console go?
//
//   * "USB CDC On Boot: Enabled"  -> `Serial` is the USB CDC port and carries
//     the host-program protocol (usb_link_arduino.cpp); Serial0 is UART0 and
//     is free for the console. With MW_SERIAL_USE_UART0 the board routes it to
//     GPIO43 TX / GPIO44 RX (needed when DIS_USB_SERIAL_JTAG is burned),
//     otherwise the core's default UART0 pins are used.
//   * "USB CDC On Boot: Disabled" -> `Serial` IS UART0 and carries the
//     protocol, so there is no UART console at all. Log lines still reach the
//     host program as framed LOG events on the same port, which is exactly
//     why debug output can never corrupt the protocol.
// ---------------------------------------------------------------------------
#include "log.h"
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#if defined(ARDUINO_USB_CDC_ON_BOOT) && (ARDUINO_USB_CDC_ON_BOOT == 1)
#  define MW_UART_CONSOLE 1
#else
#  define MW_UART_CONSOLE 0
#endif

#define MW_LOG(...)  MW_LOGI("hal", __VA_ARGS__)

static SemaphoreHandle_t s_log_mutex = NULL;

static void log_lock(void* ctx)   { if (ctx) xSemaphoreTake((SemaphoreHandle_t)ctx, portMAX_DELAY); }
static void log_unlock(void* ctx) { if (ctx) xSemaphoreGive((SemaphoreHandle_t)ctx); }

#if MW_UART_CONSOLE
static void log_uart_sink(mw_log_level_t level, const char* line, void* ctx) {
    (void)ctx;
    Serial0.write((uint8_t)mw_log_level_char(level));
    Serial0.write(' ');
    Serial0.write((const uint8_t*)line, strlen(line));
    Serial0.write("\r\n", 2);
}
#endif

static void mw_log_platform_init(void) {
    mw_log_init();
    if (!s_log_mutex) s_log_mutex = xSemaphoreCreateMutex();
    mw_log_set_lock(log_lock, log_unlock, s_log_mutex);
#if MW_UART_CONSOLE
#  if defined(MW_SERIAL_USE_UART0)
    Serial0.begin(115200, SERIAL_8N1, 44, 43);
#  else
    Serial0.begin(115200);
#  endif
    delay(50);
    mw_log_set_sink(log_uart_sink, NULL);
#endif
}
#define MW_LOG_INIT()  mw_log_platform_init()

// ===========================================================================
// Capabilities
// ===========================================================================
static mw_hal_caps_t s_caps;
static bool          s_caps_ready = false;
static bool          s_hal_ready  = false;

static void caps_fill(void)
{
    if (s_caps_ready) return;
    memset(&s_caps, 0, sizeof(s_caps));

    // Logical size: from the driver once the display is up (see
    // display_drivers.h), the expected value before that.
    s_caps.width       = mw_display_width();
    s_caps.height      = mw_display_height();
    s_caps.rotation    = DISPLAY_ROTATION;
    s_caps.monochrome  = MW_DISPLAY_MONO ? true : false;
    s_caps.has_touch   = (HAS_TOUCH && TOUCH_DRIVER != TOUCH_NONE);
    s_caps.has_buttons = (HAS_BUTTONS != 0);
    s_caps.has_encoder = (BUTTON_ENCODER_A >= 0 && BUTTON_ENCODER_B >= 0);
    s_caps.has_sd      = (HAS_SD != 0);
    s_caps.has_camera  = (HAS_CAMERA != 0);
    s_caps.has_usb     = (HAS_USB_OTG != 0);
    s_caps.has_psram   = (HAS_PSRAM != 0);
    // Report what the chip actually has, not what the header hoped for.
    s_caps.psram_size_mb = (uint32_t)(ESP.getPsramSize() / (1024u * 1024u));
    s_caps.board_name  = BOARD_NAME;
    s_caps_ready = true;
}

const mw_hal_caps_t* mw_hal_caps(void)
{
    caps_fill();
    return &s_caps;
}

// ===========================================================================
// Init
// ===========================================================================
static mw_err_t psram_check(void)
{
#if HAS_PSRAM
    if (!psramFound()) {
        MW_LOGE("hal", "board %s declares %d MB PSRAM, none detected.",
               BOARD_NAME, (int)PSRAM_SIZE_MB);
        return MW_ERR_MEMORY;
    }

    const size_t total = ESP.getPsramSize();
    const size_t want  = (size_t)PSRAM_SIZE_MB * 1024u * 1024u;
    if (total + (256u * 1024u) < want) {      // allow the usual reserve
        MW_LOGE("hal", "PSRAM is %u MB, board_config.h promises %d MB.",
               (unsigned)(total / (1024u * 1024u)), (int)PSRAM_SIZE_MB);
        return MW_ERR_MEMORY;
    }

    // TZ 1.4: cn_slow_hash needs a single 2 MB contiguous scratchpad.  The
    // check is done at boot, while the heap is still pristine - discovering
    // it during a signature would mean aborting a half-built transaction.
    const size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if (largest < 2u * 1024u * 1024u) {
        MW_LOGE("hal", "largest contiguous PSRAM block is %u KB, need 2048 KB.",
               (unsigned)(largest / 1024u));
        return MW_ERR_MEMORY;
    }
    MW_LOG("PSRAM: %u MB total, %u KB largest block.",
           (unsigned)(total / (1024u * 1024u)), (unsigned)(largest / 1024u));
#endif
    return MW_OK;
}

// ===========================================================================
// Crash diagnostics: reset reason and the RTC breadcrumb
// ===========================================================================
// RTC_NOINIT memory keeps its content across a panic / watchdog reset but not
// a power cycle. The crumb holds enums and a stack figure only.
#define MW_CRUMB_MAGIC 0x4D57434Bu          // "MWCK"

struct mw_crumb_t {
    uint32_t magic;
    uint8_t  op, stage, rsv0, rsv1;
    uint32_t stack_free;
    uint32_t check;
};
static RTC_NOINIT_ATTR mw_crumb_t s_crumb;
static mw_crumb_t s_last;                   // valid when s_last.magic == MAGIC
static uint8_t    s_reset_reason = MW_RESET_UNKNOWN;

static uint32_t crumb_check(const mw_crumb_t* c)
{
    return (c->magic ^ ((uint32_t)c->op << 8) ^ ((uint32_t)c->stage << 16) ^
            c->stack_free) * 2654435761u;
}

static uint8_t map_reset_reason(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON:   return MW_RESET_POWERON;
    case ESP_RST_EXT:       return MW_RESET_EXTERNAL;
    case ESP_RST_SW:        return MW_RESET_SOFTWARE;
    case ESP_RST_PANIC:     return MW_RESET_PANIC;
    case ESP_RST_INT_WDT:   return MW_RESET_INT_WDT;
    case ESP_RST_TASK_WDT:  return MW_RESET_TASK_WDT;
    case ESP_RST_WDT:       return MW_RESET_WDT;
    case ESP_RST_DEEPSLEEP: return MW_RESET_DEEPSLEEP;
    case ESP_RST_BROWNOUT:  return MW_RESET_BROWNOUT;
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 1, 0)
    case ESP_RST_USB:
    case ESP_RST_JTAG:      return MW_RESET_USB;
#endif
    case ESP_RST_UNKNOWN:   return MW_RESET_UNKNOWN;
    default:                return MW_RESET_OTHER;
    }
}

// Runs once at boot, before anything can set a new crumb.
static void crash_capture(void)
{
    s_reset_reason = map_reset_reason(esp_reset_reason());
    const bool crash = s_reset_reason == MW_RESET_PANIC || s_reset_reason == MW_RESET_INT_WDT ||
                       s_reset_reason == MW_RESET_TASK_WDT || s_reset_reason == MW_RESET_WDT ||
                       s_reset_reason == MW_RESET_BROWNOUT;
    memset(&s_last, 0, sizeof s_last);
    if (crash && s_crumb.magic == MW_CRUMB_MAGIC && s_crumb.check == crumb_check(&s_crumb) &&
        s_crumb.op != MW_CRUMB_OP_NONE) {
        s_last = s_crumb;
    }
    memset(&s_crumb, 0, sizeof s_crumb);
}

uint8_t mw_hal_reset_reason(void) { return s_reset_reason; }

void mw_hal_crumb_set(uint8_t op, uint8_t stage)
{
    mw_crumb_t c;
    memset(&c, 0, sizeof c);
    c.magic = MW_CRUMB_MAGIC;
    c.op = op;
    c.stage = stage;
    c.stack_free = mw_stack_free_min();
    c.check = crumb_check(&c);
    s_crumb = c;
}

void mw_hal_crumb_clear(void) { memset(&s_crumb, 0, sizeof s_crumb); }

bool mw_hal_last_crash(uint8_t* op, uint8_t* stage)
{
    if (s_last.magic != MW_CRUMB_MAGIC) return false;
    if (op) *op = s_last.op;
    if (stage) *stage = s_last.stage;
    return true;
}

uint32_t mw_hal_last_crash_stack_free(void)
{
    return s_last.magic == MW_CRUMB_MAGIC ? s_last.stack_free : 0;
}

void mw_hal_last_crash_forget(void) { memset(&s_last, 0, sizeof s_last); }

uint32_t mw_stack_free_min(void)
{
    // ESP-IDF counts stack in bytes (StackType_t is uint8_t).
    return (uint32_t)uxTaskGetStackHighWaterMark(NULL) * (uint32_t)sizeof(StackType_t);
}

mw_err_t mw_hal_init(void)
{
    if (s_hal_ready) return MW_OK;
    crash_capture();

    MW_LOG_INIT();
    MW_LOG("");
    MW_LOG("%s %s on %s", MW_FIRMWARE_NAME, MW_FIRMWARE_VERSION, BOARD_NAME);

    // --- 1. TRNG (TZ 8.2) -------------------------------------------------
    mw_rng_status_t rng = mw_random_init();
    if (rng != MW_RNG_OK) {
        MW_LOGE("hal", "RNG init/self-test failed (%d). Refusing to boot.",
                (int)rng);
        return MW_ERR_IO;
    }

    // --- 2. PSRAM ---------------------------------------------------------
    mw_err_t e = psram_check();
    if (e != MW_OK) return e;

    // NVS is intentionally NOT initialised here: wallet/secure_storage.cpp
    // owns it and must bring it up through nvs_flash_secure_init() with the
    // eFuse HMAC key (TZ 8.1).  A plain nvs_flash_init() first would bind the
    // partition unencrypted.

    // --- 3. Display -------------------------------------------------------
    e = mw_display_init();
    if (e != MW_OK) {
        MW_LOGE("hal", "display init failed (%d).", (int)e);
        return e;
    }
    mw_display_backlight(100);

    // --- 4. Inputs (both optional, neither fatal) -------------------------
    // Refill: something may have read the caps before the driver was up and
    // the logical size is only known now.
    s_caps_ready = false;
    caps_fill();
    if (s_caps.has_touch) {
        e = mw_touch_init();
        if (e != MW_OK) MW_LOGE("hal", "touch init failed (%d).", (int)e);
    }
    if (s_caps.has_buttons || s_caps.has_encoder) {
        e = mw_buttons_init();
        if (e != MW_OK) MW_LOGE("hal", "button init failed (%d).", (int)e);
    }
    if (!s_caps.has_touch && !s_caps.has_buttons) {
        // No indev at all would leave the UI unusable (TZ 2.5).
        MW_LOGE("hal", "board has neither touch nor buttons.");
        return MW_ERR_NOT_SUPPORTED;
    }

    // --- 5. SD (optional: the slot is usually empty at boot) --------------
    if (s_caps.has_sd) {
        // Probe only: the card is mounted again for each use and released
        // right after it (mw_sd_ensure / mw_sd_release), so it can be swapped
        // while the device runs.
        e = mw_sd_init();
        if (e != MW_OK) MW_LOG("SD: no card at boot (%d).", (int)e);
        else            MW_LOG("SD: card present.");
        mw_sd_release();
    }

    s_hal_ready = true;
    MW_LOG("HAL ready: %ux%u%s, heap %u KB.",
           (unsigned)s_caps.width, (unsigned)s_caps.height,
           s_caps.monochrome ? " mono" : "",
           (unsigned)(ESP.getFreeHeap() / 1024u));
    return MW_OK;
}

void mw_hal_deinit(void)
{
    if (!s_hal_ready) return;
    // The camera may have been brought up lazily by the QR screen; shutting
    // the HAL down with a sensor still streaming would leak both the PSRAM
    // framebuffers and the LEDC channel driving XCLK.
    mw_camera_deinit();
    mw_display_backlight(0);
    s_hal_ready = false;
}

// ===========================================================================
// Power
// ===========================================================================
int mw_battery_percent(void)
{
#if BATTERY_ADC_PIN >= 0
    // Eight samples through the calibrated ADC path; the divider is on the
    // board, so the header supplies its ratio.
    uint32_t acc = 0;
    for (int i = 0; i < 8; ++i) acc += analogReadMilliVolts(BATTERY_ADC_PIN);
    uint32_t mv = (acc / 8u) * (uint32_t)BATTERY_DIV_NUM
                             / (uint32_t)BATTERY_DIV_DEN;

    // Linear voltage-to-percent. Crude for a Li-ion discharge curve, but this
    // is a status-bar icon (TZ 4.2), not a fuel gauge, and it never lies in
    // the direction that matters: a nearly empty cell reads nearly empty.
    if (mv <= BATTERY_MV_EMPTY) return 0;
    if (mv >= BATTERY_MV_FULL)  return 100;
    return (int)(((mv - BATTERY_MV_EMPTY) * 100u)
                 / (BATTERY_MV_FULL - BATTERY_MV_EMPTY));
#else
    return -1;                          // no fuel gauge on this board
#endif
}

bool mw_usb_connected(void)
{
#if USB_VBUS_DET_PIN >= 0
    pinMode(USB_VBUS_DET_PIN, INPUT);
    return digitalRead(USB_VBUS_DET_PIN) == HIGH;   // VBUS through a divider
#elif defined(ARDUINO_USB_CDC_ON_BOOT) && (ARDUINO_USB_CDC_ON_BOOT == 1)
    // The CDC device reports DTR, which is set once a host enumerates and
    // opens the port.  Not a VBUS sense, but it answers the question the UI
    // actually asks: "is a computer talking to me?"
    return (bool)Serial;
#else
    return false;
#endif
}

// ===========================================================================
// Misc
// ===========================================================================
uint32_t mw_millis(void)            { return (uint32_t)millis(); }
void     mw_delay_ms(uint32_t ms)   { delay(ms); }

void mw_reboot(void)
{
    mw_display_backlight(0);
    delay(20);
    esp_restart();
}

// ***************************************************************************
// *                                                                         *
// *   FACTORY RESET - THIS DESTROYS EVERY WALLET ON THE DEVICE.             *
// *                                                                         *
// *   It erases the whole NVS partition: all seeds, all spend/view keys,    *
// *   all wallet names and restore heights, the key-image cache and every   *
// *   setting.  There is no undo and no backup anywhere on the device.      *
// *   Anyone who has not written down their seed phrase loses their funds.  *
// *                                                                         *
// *   Callers MUST have obtained an explicit, typed confirmation from the   *
// *   user first (TZ 4.2).  Never call this from an error path.             *
// *                                                                         *
// *   Note: the eFuse HMAC key is NOT erased - eFuses are one-time          *
// *   programmable (TZ 8.1).  It does not need to be: without the NVS       *
// *   ciphertext the key decrypts nothing.                                  *
// *                                                                         *
// ***************************************************************************
void mw_factory_reset(void)
{
    MW_LOGE("hal", "FACTORY RESET: erasing NVS - all wallets are being destroyed.");

    // Close the partition first: nvs_flash_erase() on a mounted partition is
    // refused, and a half-erased NVS would leave recoverable key material.
    (void)nvs_flash_deinit();

    esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK) {
        // Fall back to erasing the raw partition so no ciphertext survives
        // even if the NVS layer itself is the thing that is broken.
        const esp_partition_t* p = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        if (p) (void)esp_partition_erase_range(p, 0, p->size);
    }

    mw_display_backlight(0);
    delay(100);
    esp_restart();
}

#endif  // ARDUINO && !MW_HOST_BUILD