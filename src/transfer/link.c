// ============================================================================
// USB link protocol core - see link.h for the wire format.
//
// Platform independent: no USB, no FreeRTOS, no Arduino. The transports
// (usb_link_arduino.cpp) push bytes into mw_link_rx_t, hand complete messages
// to mw_link_handle() and send back whatever it produces. The UI flows talk
// to the inbox/outbox through transfer.c.
//
// Threading: the inbox/outbox are touched from the link task (PUT/GET/STATUS)
// and from the crypto task (take/put). Every access goes through
// store_lock()/store_unlock(), which the port supplies; on the host they are
// no-ops because the tests are single-threaded.
//
// SPDX-License-Identifier: MIT
// ============================================================================
#include "link.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../hal/hal.h"

#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------
static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ===========================================================================
// COBS
// ===========================================================================
size_t mw_cobs_max_encoded(size_t len) {
    // One code byte per 254 data bytes (rounded up) plus the leading code byte;
    // +1 more keeps the bound conservative for the trailing empty block.
    return len + len / 254u + 2u;
}

size_t mw_cobs_encode(const uint8_t* in, size_t len, uint8_t* out, size_t cap) {
    if ((!in && len) || !out) return 0;
    if (cap < mw_cobs_max_encoded(len)) return 0;

    size_t  read = 0, write = 1, code_idx = 0;
    uint8_t code = 1;

    while (read < len) {
        uint8_t b = in[read++];
        if (b == 0) {
            out[code_idx] = code;
            code_idx = write++;
            code = 1;
        } else {
            out[write++] = b;
            if (++code == 0xFF) {
                out[code_idx] = code;
                code_idx = write++;
                code = 1;
            }
        }
    }
    out[code_idx] = code;
    return write;
}

mw_err_t mw_cobs_decode(const uint8_t* in, size_t len, uint8_t* out, size_t cap,
                        size_t* out_len) {
    if (!in || !out || !out_len) return MW_ERR_INVALID_ARG;
    size_t read = 0, write = 0;

    while (read < len) {
        uint8_t code = in[read++];
        if (code == 0) return MW_ERR_FORMAT;            // delimiter inside a frame
        size_t run = (size_t)code - 1u;
        if (read + run > len)   return MW_ERR_FORMAT;   // truncated block
        if (write + run > cap)  return MW_ERR_TOO_MANY;
        // Forward byte copy: `out` may alias `in`, and write never overtakes
        // read (write <= read - 1 at every step), so in-place decoding holds.
        for (size_t i = 0; i < run; ++i) {
            uint8_t b = in[read++];
            if (b == 0) return MW_ERR_FORMAT;
            out[write++] = b;
        }
        if (code != 0xFF && read < len) {
            if (write >= cap) return MW_ERR_TOO_MANY;
            out[write++] = 0;
        }
    }
    *out_len = write;
    return MW_OK;
}

// ===========================================================================
// Messages
// ===========================================================================
size_t mw_link_msg_size(uint32_t payload_len) {
    return (size_t)MW_LINK_OVERHEAD + (size_t)payload_len;
}

const uint8_t mw_link_magic[MW_LINK_MAGIC_LEN] = MW_LINK_MAGIC_BYTES;

uint8_t* mw_link_msg_begin(uint8_t cmd, uint8_t arg, uint32_t len,
                           uint8_t* out, size_t cap) {
    if (!out) return NULL;
    if (len > MW_LINK_MAX_PAYLOAD) return NULL;
    if (cap < mw_link_msg_size(len)) return NULL;
    memcpy(out, mw_link_magic, MW_LINK_MAGIC_LEN);
    out[8]  = MW_LINK_PROTO_VERSION;
    out[9]  = cmd;
    out[10] = arg;
    out[11] = 0;
    put_u32(out + 12, len);
    put_u32(out + MW_LINK_HDR_CRC_OFF, mw_crc32(out, MW_LINK_HDR_CRC_OFF));
    return out + MW_LINK_HDR_LEN;
}

bool mw_link_hdr_valid(const uint8_t* hdr, size_t avail, uint32_t* payload_len) {
    if (!hdr || avail < MW_LINK_HDR_LEN) return false;
    if (memcmp(hdr, mw_link_magic, MW_LINK_MAGIC_LEN) != 0) return false;
    if (hdr[8] != MW_LINK_PROTO_VERSION) return false;
    if (get_u32(hdr + MW_LINK_HDR_CRC_OFF) != mw_crc32(hdr, MW_LINK_HDR_CRC_OFF))
        return false;
    if (payload_len) *payload_len = get_u32(hdr + 12);
    return true;
}

size_t mw_link_msg_finish(uint8_t* out, uint32_t len) {
    size_t body = (size_t)MW_LINK_HDR_LEN + (size_t)len;
    put_u32(out + body, mw_crc32(out, body));
    return body + MW_LINK_CRC_LEN;
}

mw_err_t mw_link_msg_build(uint8_t cmd, uint8_t arg, const uint8_t* payload,
                           uint32_t len, uint8_t* out, size_t cap, size_t* out_len) {
    if (!out || (len && !payload)) return MW_ERR_INVALID_ARG;
    if (len > MW_LINK_MAX_PAYLOAD)   return MW_ERR_TOO_MANY;
    uint8_t* p = mw_link_msg_begin(cmd, arg, len, out, cap);
    if (!p) return MW_ERR_TOO_MANY;
    if (len) memcpy(p, payload, len);
    size_t n = mw_link_msg_finish(out, len);
    if (out_len) *out_len = n;
    return MW_OK;
}

mw_err_t mw_link_msg_parse(const uint8_t* buf, size_t len, mw_link_msg_t* out) {
    if (!buf || !out) return MW_ERR_INVALID_ARG;
    if (len < MW_LINK_OVERHEAD) return MW_ERR_FORMAT;
    if (memcmp(buf, mw_link_magic, MW_LINK_MAGIC_LEN) != 0 ||
        buf[8] != MW_LINK_PROTO_VERSION) return MW_ERR_MAGIC;
    if (get_u32(buf + MW_LINK_HDR_CRC_OFF) != mw_crc32(buf, MW_LINK_HDR_CRC_OFF))
        return MW_ERR_CHECKSUM;

    uint32_t plen = get_u32(buf + 12);
    if (plen > MW_LINK_MAX_PAYLOAD) return MW_ERR_TOO_MANY;
    if (mw_link_msg_size(plen) != len) return MW_ERR_FORMAT;

    size_t body = (size_t)MW_LINK_HDR_LEN + plen;
    if (get_u32(buf + body) != mw_crc32(buf, body)) return MW_ERR_CHECKSUM;

    out->cmd     = buf[9];
    out->arg     = buf[10];
    out->len     = plen;
    out->payload = buf + MW_LINK_HDR_LEN;
    return MW_OK;
}

// ===========================================================================
// Outgoing framing
// ===========================================================================
size_t mw_link_serial_frame(const uint8_t* msg, size_t len, uint8_t* out, size_t cap) {
    if (!msg || !out || cap == 0) return 0;
    size_t n = mw_cobs_encode(msg, len, out, cap - 1);
    if (n == 0) return 0;
    out[n++] = 0x00;
    return n;
}

size_t mw_link_hid_report_count(size_t msg_len) {
    if (msg_len <= MW_LINK_HID_FIRST_DATA) return 1;
    size_t rest = msg_len - MW_LINK_HID_FIRST_DATA;
    return 1 + (rest + MW_LINK_HID_CONT_DATA - 1) / MW_LINK_HID_CONT_DATA;
}

void mw_link_hid_report(const uint8_t* msg, size_t len, size_t index,
                        uint8_t out[MW_LINK_HID_DATA]) {
    memset(out, 0, MW_LINK_HID_DATA);
    if (!msg) return;
    if (index == 0) {
        out[0] = '?'; out[1] = '#'; out[2] = '#';
        size_t n = len < MW_LINK_HID_FIRST_DATA ? len : MW_LINK_HID_FIRST_DATA;
        memcpy(out + MW_LINK_HID_FIRST_HDR, msg, n);
        return;
    }
    size_t off = MW_LINK_HID_FIRST_DATA + (index - 1) * MW_LINK_HID_CONT_DATA;
    out[0] = '?';
    if (off >= len) return;
    size_t n = len - off;
    if (n > MW_LINK_HID_CONT_DATA) n = MW_LINK_HID_CONT_DATA;
    memcpy(out + MW_LINK_HID_CONT_HDR, msg + off, n);
}

// ===========================================================================
// Receiver
// ===========================================================================
void mw_link_rx_init(mw_link_rx_t* rx, mw_link_transport_t t, uint8_t* buf, size_t cap) {
    memset(rx, 0, sizeof(*rx));
    rx->transport = t;
    rx->buf = buf;
    rx->cap = cap;
}

void mw_link_rx_reset(mw_link_rx_t* rx) {
    rx->len = 0;
    rx->expect = 0;
    rx->in_frame = false;
    rx->overflow = false;
    rx->ready = false;
}

static bool rx_feed_serial(mw_link_rx_t* rx, const uint8_t* data, size_t n, size_t* consumed) {
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = data[i];
        if (b != 0x00) {
            if (rx->overflow) continue;
            if (rx->len >= rx->cap) { rx->overflow = true; continue; }
            rx->buf[rx->len++] = b;
            continue;
        }
        // Delimiter.
        *consumed = i + 1;
        if (rx->overflow) {
            rx->dropped++;
            mw_link_rx_reset(rx);
            continue;                     // keep scanning the same chunk
        }
        if (rx->len == 0) continue;       // idle / resync zero
        size_t decoded = 0;
        mw_err_t e = mw_cobs_decode(rx->buf, rx->len, rx->buf, rx->cap, &decoded);
        if (e != MW_OK) {
            rx->dropped++;
            mw_link_rx_reset(rx);
            continue;
        }
        rx->len = decoded;
        rx->ready = true;
        return true;
    }
    *consumed = n;
    return false;
}

static bool rx_feed_hid(mw_link_rx_t* rx, const uint8_t* data, size_t n, size_t* consumed) {
    *consumed = n;
    if (n < MW_LINK_HID_FIRST_HDR) return false;

    const uint8_t* body;
    size_t         body_len;

    // A frame starts only on "?##" followed by a complete, valid header (8
    // magic bytes, version, header CRC - all inside this one report): random
    // continuation data starting with "##" must not restart the receiver.
    if (n >= MW_LINK_HID_FIRST_HDR + MW_LINK_HDR_LEN &&
        data[0] == '?' && data[1] == '#' && data[2] == '#' &&
        mw_link_hdr_valid(data + MW_LINK_HID_FIRST_HDR, n - MW_LINK_HID_FIRST_HDR, NULL)) {
        if (rx->in_frame) rx->dropped++;   // previous frame never completed
        mw_link_rx_reset(rx);
        rx->in_frame = true;
        body     = data + MW_LINK_HID_FIRST_HDR;
        body_len = n - MW_LINK_HID_FIRST_HDR;
    } else if (data[0] == '?' && rx->in_frame) {
        body     = data + MW_LINK_HID_CONT_HDR;
        body_len = n - MW_LINK_HID_CONT_HDR;
    } else {
        rx->dropped++;                     // stray report
        return false;
    }

    if (rx->len > rx->cap) rx->len = rx->cap;
    size_t room = rx->cap - rx->len;
    if (body_len > room) body_len = room;
    memcpy(rx->buf + rx->len, body, body_len);
    rx->len += body_len;

    if (rx->expect == 0 && rx->len >= MW_LINK_HDR_LEN) {
        uint32_t plen = 0;
        if (!mw_link_hdr_valid(rx->buf, rx->len, &plen)) {
            rx->dropped++;
            mw_link_rx_reset(rx);
            return false;
        }
        if (plen > MW_LINK_MAX_PAYLOAD || mw_link_msg_size(plen) > rx->cap) {
            rx->dropped++;
            mw_link_rx_reset(rx);
            return false;
        }
        rx->expect = mw_link_msg_size(plen);
    }

    if (rx->expect && rx->len >= rx->expect) {
        rx->len = rx->expect;              // drop the zero padding
        rx->ready = true;
        return true;
    }
    if (rx->len >= rx->cap) {              // buffer full without a frame end
        rx->dropped++;
        mw_link_rx_reset(rx);
    }
    return false;
}

bool mw_link_rx_feed(mw_link_rx_t* rx, const uint8_t* data, size_t n, size_t* consumed) {
    size_t dummy;
    if (!consumed) consumed = &dummy;
    *consumed = 0;
    if (!rx || !rx->buf || !data) return false;
    if (rx->ready) return true;            // caller forgot to reset
    if (rx->transport == MW_LINK_TRANSPORT_HID) return rx_feed_hid(rx, data, n, consumed);
    return rx_feed_serial(rx, data, n, consumed);
}

// ===========================================================================
// Store
// ===========================================================================
typedef struct {
    uint8_t* data;
    size_t   len;
} slot_t;

static struct {
    bool            inited;
    bool            up;
    uint8_t         caps;
    slot_t          inbox[MW_LINK_FILE_KINDS];
    slot_t          outbox[MW_LINK_FILE_KINDS];
    mw_link_port_t  port;
    mw_link_info_fn info_fn;
    void*           info_ctx;
    mw_link_wait_hook_t wait_hook;
    void*           wait_ctx;
    // v2
    uint8_t         state;
    uint8_t         accept_mask;
    volatile uint8_t request;
    uint32_t        seq;
    mw_link_classify_fn classify;
    mw_link_event_fn event_fn;
    void*           event_ctx;
} g;

static void  store_lock(void)   { if (g.port.lock)   g.port.lock(g.port.ctx); }
static void  store_unlock(void) { if (g.port.unlock) g.port.unlock(g.port.ctx); }
static void* store_alloc(size_t n) { return g.port.alloc ? g.port.alloc(n) : malloc(n); }
static void  store_free(void* p, size_t n) {
    if (!p) return;
    mw_memzero(p, n);                      // files are ciphertext, but be tidy
    if (g.port.free) g.port.free(p, n); else free(p);
}

static void slot_clear(slot_t* s) {
    store_free(s->data, s->len);
    s->data = NULL;
    s->len  = 0;
}

// Replaces the slot content. Allocates first so a failed allocation leaves
// the previous file (a retransmit-able outbox entry, say) untouched.
static mw_err_t slot_set(slot_t* s, const uint8_t* buf, size_t len) {
    uint8_t* p = (uint8_t*)store_alloc(len);
    if (!p) return MW_ERR_MEMORY;
    memcpy(p, buf, len);
    slot_clear(s);
    s->data = p;
    s->len  = len;
    return MW_OK;
}

static bool kind_ok(unsigned kind) { return kind < MW_LINK_FILE_KINDS; }

mw_err_t mw_link_init(void) {
    if (g.inited) {
        store_lock();
        for (int i = 0; i < MW_LINK_FILE_KINDS; ++i) {
            slot_clear(&g.inbox[i]);
            slot_clear(&g.outbox[i]);
        }
        store_unlock();
        return MW_OK;
    }
    mw_link_port_t port = g.port;          // may have been set before init
    mw_link_info_fn fn = g.info_fn; void* fctx = g.info_ctx;
    mw_link_wait_hook_t wh = g.wait_hook; void* wctx = g.wait_ctx;
    mw_link_classify_fn cl = g.classify;
    mw_link_event_fn ev = g.event_fn; void* ectx = g.event_ctx;
    uint8_t st = g.state, am = g.accept_mask;
    memset(&g, 0, sizeof(g));
    g.port = port; g.info_fn = fn; g.info_ctx = fctx;
    g.wait_hook = wh; g.wait_ctx = wctx;
    g.classify = cl; g.event_fn = ev; g.event_ctx = ectx;
    g.state = st; g.accept_mask = am;
    g.inited = true;
    return MW_OK;
}

void mw_link_deinit(void) {
    if (!g.inited) return;
    store_lock();
    for (int i = 0; i < MW_LINK_FILE_KINDS; ++i) {
        slot_clear(&g.inbox[i]);
        slot_clear(&g.outbox[i]);
    }
    store_unlock();
    g.inited = false;
    g.up = false;
    g.caps = 0;
}

void mw_link_set_port(const mw_link_port_t* port) {
    if (port) g.port = *port;
    else      memset(&g.port, 0, sizeof(g.port));
}

void mw_link_set_info_provider(mw_link_info_fn fn, void* ctx) {
    g.info_fn = fn;
    g.info_ctx = ctx;
}

void    mw_link_set_up(bool up, uint8_t caps) { g.up = up; g.caps = caps; }
bool    mw_link_is_up(void)                   { return g.inited && g.up; }
uint8_t mw_link_caps(void)                    { return g.caps; }

// ---- firmware side --------------------------------------------------------
void mw_link_set_state(uint8_t state, uint8_t accept_mask) {
    store_lock();
    if (g.state != state || g.accept_mask != accept_mask) g.seq++;
    g.state = state;
    g.accept_mask = accept_mask;
    // A request is only meaningful while a wallet is open.
    if (state != MW_LINK_STATE_WALLET && state != MW_LINK_STATE_BUSY) g.request = 0;
    store_unlock();
}

uint8_t mw_link_state(void) {
    store_lock();
    uint8_t s = g.state;
    store_unlock();
    return s;
}

void mw_link_set_classifier(mw_link_classify_fn fn) { g.classify = fn; }

void mw_link_set_event_hook(mw_link_event_fn fn, void* ctx) {
    g.event_fn = fn;
    g.event_ctx = ctx;
}

uint8_t mw_link_request_peek(void) { return g.request; }

uint8_t mw_link_request_take(void) {
    store_lock();
    uint8_t r = g.request;
    g.request = 0;
    store_unlock();
    return r;
}

void mw_link_bump_seq(void) {
    store_lock();
    g.seq++;
    store_unlock();
}

int mw_link_inbox_any(size_t* len) {
    if (!g.inited) return -1;
    int found = -1;
    store_lock();
    for (int i = 0; i < MW_LINK_FILE_KINDS; ++i) {
        if (g.inbox[i].data) {
            found = i;
            if (len) *len = g.inbox[i].len;
            break;
        }
    }
    store_unlock();
    return found;
}

static void fire_event(void) {
    if (g.event_fn) g.event_fn(g.event_ctx);
}

bool mw_link_inbox_pending(mw_file_kind_id_t kind, size_t* len) {
    if (!g.inited || !kind_ok((unsigned)kind)) return false;
    store_lock();
    bool pending = g.inbox[kind].data != NULL;
    if (len) *len = g.inbox[kind].len;
    store_unlock();
    return pending;
}

mw_err_t mw_link_inbox_take(mw_file_kind_id_t kind, uint8_t* buf, size_t cap, size_t* len) {
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if (!g.inited || !kind_ok((unsigned)kind)) return MW_ERR_INVALID_ARG;
    mw_err_t e;
    store_lock();
    slot_t* s = &g.inbox[kind];
    if (!s->data) {
        e = MW_ERR_NOT_SUPPORTED;          // "nothing there" - callers poll
    } else if (s->len > cap) {
        e = MW_ERR_TOO_MANY;               // leave it; the caller may retry bigger
    } else {
        memcpy(buf, s->data, s->len);
        if (len) *len = s->len;
        slot_clear(s);
        e = MW_OK;
    }
    store_unlock();
    return e;
}

void mw_link_inbox_clear(mw_file_kind_id_t kind) {
    if (!g.inited || !kind_ok((unsigned)kind)) return;
    store_lock();
    slot_clear(&g.inbox[kind]);
    store_unlock();
}

mw_err_t mw_link_outbox_put(mw_file_kind_id_t kind, const uint8_t* buf, size_t len) {
    if (!buf || len == 0) return MW_ERR_INVALID_ARG;
    if (!g.inited || !kind_ok((unsigned)kind)) return MW_ERR_INVALID_ARG;
    if (len > MW_LINK_MAX_PAYLOAD) return MW_ERR_TOO_MANY;
    store_lock();
    mw_err_t e = slot_set(&g.outbox[kind], buf, len);
    if (e == MW_OK) g.seq++;
    store_unlock();
    return e;
}

bool mw_link_outbox_pending(mw_file_kind_id_t kind, size_t* len) {
    if (!g.inited || !kind_ok((unsigned)kind)) return false;
    store_lock();
    bool pending = g.outbox[kind].data != NULL;
    if (len) *len = g.outbox[kind].len;
    store_unlock();
    return pending;
}

void mw_link_outbox_clear(mw_file_kind_id_t kind) {
    if (!g.inited || !kind_ok((unsigned)kind)) return;
    store_lock();
    slot_clear(&g.outbox[kind]);
    store_unlock();
}

void mw_link_set_wait_hook(mw_link_wait_hook_t hook, void* ctx) {
    g.wait_hook = hook;
    g.wait_ctx = ctx;
}

mw_err_t mw_link_wait_inbox(mw_file_kind_id_t kind, uint8_t* buf, size_t cap,
                            size_t* len, uint32_t timeout_ms) {
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if (!g.inited || !kind_ok((unsigned)kind)) return MW_ERR_INVALID_ARG;

    const uint32_t t0 = mw_millis();
    for (;;) {
        mw_err_t e = mw_link_inbox_take(kind, buf, cap, len);
        if (e != MW_ERR_NOT_SUPPORTED) return e;    // got it, or a real error

        uint32_t elapsed = mw_millis() - t0;
        if (g.wait_hook && !g.wait_hook(elapsed, g.wait_ctx)) return MW_ERR_ABORTED;
        if (timeout_ms && elapsed >= timeout_ms) return MW_ERR_IO;
        mw_delay_ms(MW_LINK_POLL_MS);
    }
}

// ===========================================================================
// Dispatcher
// ===========================================================================
static size_t reply_error(uint8_t code, const char* text, uint8_t* out, size_t cap) {
    size_t n = 0;
    size_t tlen = text ? strlen(text) : 0;
    if (mw_link_msg_build(MW_LINK_RSP_ERROR, code, (const uint8_t*)text,
                          (uint32_t)tlen, out, cap, &n) != MW_OK) {
        if (mw_link_msg_build(MW_LINK_RSP_ERROR, code, NULL, 0, out, cap, &n) != MW_OK)
            return 0;
    }
    return n;
}

static void fill_lens(uint8_t* p) {
    // Caller holds the lock.
    for (int i = 0; i < MW_LINK_FILE_KINDS; ++i)
        put_u32(p + 4 * i, (uint32_t)g.inbox[i].len);
    for (int i = 0; i < MW_LINK_FILE_KINDS; ++i)
        put_u32(p + 4 * MW_LINK_FILE_KINDS + 4 * i, (uint32_t)g.outbox[i].len);
}

static size_t reply_info(uint8_t* out, size_t cap) {
    uint8_t* p = mw_link_msg_begin(MW_LINK_RSP_INFO, 0, MW_LINK_INFO_WIRE_LEN, out, cap);
    if (!p) return 0;
    memset(p, 0, MW_LINK_INFO_WIRE_LEN);

    mw_link_info_t info;
    memset(&info, 0, sizeof(info));
    if (g.info_fn) g.info_fn(&info, g.info_ctx);

    p[0] = MW_LINK_PROTO_VERSION;
    p[1] = (uint8_t)(g.caps | MW_LINK_CAP_AUTO_KIND | MW_LINK_CAP_REQ);
    store_lock();
    p[2] = g.state;
    store_unlock();
    p[3] = info.network;
    put_u32(p + 4, MW_LINK_MAX_PAYLOAD);
    p[8]  = info.wallet_count;
    p[9]  = info.unlocked ? 1 : 0;
    p[10] = info.pp_variant ? 1 : 0;
    p[11] = MW_LINK_FILE_KINDS;
    // Bounded copies: at most sizeof(field) - 1 bytes and never past a NUL,
    // so the wire fields stay NUL terminated whatever the provider wrote.
    _Static_assert(sizeof(info.fw_version) == 16, "INFO layout");
    _Static_assert(sizeof(info.board) == 32 && sizeof(info.wallet_name) == 32, "INFO layout");
    info.fw_version[sizeof(info.fw_version) - 1]   = '\0';
    info.board[sizeof(info.board) - 1]             = '\0';
    info.wallet_name[sizeof(info.wallet_name) - 1] = '\0';
    memcpy(p + 12, info.fw_version, strlen(info.fw_version));
    memcpy(p + 28, info.board, strlen(info.board));
    memcpy(p + 60, info.wallet_name, strlen(info.wallet_name));
    // Diagnostics: the reset reason is a generic enum and always reported;
    // what the device was doing when it crashed only once it is unlocked.
    p[92] = info.reset_reason;
    if (info.unlocked) {
        p[93] = info.crash_op;
        p[94] = info.crash_stage;
        p[95] = info.crash_flags;
        p[96] = (uint8_t)info.crash_stack_free;
        p[97] = (uint8_t)(info.crash_stack_free >> 8);
    }
    return mw_link_msg_finish(out, MW_LINK_INFO_WIRE_LEN);
}

static size_t reply_status(uint8_t* out, size_t cap) {
    uint8_t* p = mw_link_msg_begin(MW_LINK_RSP_STATUS, 0, MW_LINK_STATUS_WIRE_LEN, out, cap);
    if (!p) return 0;
    memset(p, 0, MW_LINK_STATUS_WIRE_LEN);
    store_lock();
    fill_lens(p);
    p[40] = g.state;
    p[41] = g.request;
    p[42] = g.accept_mask;
    put_u32(p + 44, g.seq);
    store_unlock();
    return mw_link_msg_finish(out, MW_LINK_STATUS_WIRE_LEN);
}

static size_t reply_put(const mw_link_msg_t* m, uint8_t* out, size_t cap) {
    size_t n = 0;
    uint8_t kind = m->arg;
    if (m->len == 0) return reply_error(MW_LINK_ERR_BAD_LEN, "empty file", out, cap);

    if (kind == MW_LINK_KIND_AUTO) {
        char why[96];
        why[0] = '\0';
        const int k = g.classify ? g.classify(m->payload, m->len, why, sizeof why) : -1;
        if (k < 0 || !kind_ok((unsigned)k)) {
            return reply_error(MW_LINK_ERR_BAD_FORMAT,
                               why[0] ? why : "not a Monero exchange file", out, cap);
        }
        kind = (uint8_t)k;
    } else if (!kind_ok(kind)) {
        return reply_error(MW_LINK_ERR_BAD_KIND, "bad file kind", out, cap);
    }

    // State, mask and slot are read and changed under one lock: the shell
    // may switch the state from the UI task between the check and the store.
    store_lock();
    const uint8_t state = g.state;
    const uint8_t mask  = g.accept_mask;
    if (state == MW_LINK_STATE_BUSY) {
        store_unlock();
        return reply_error(MW_LINK_ERR_BUSY,
                           "the device is busy with the previous file: finish or cancel it "
                           "on the device", out, cap);
    }
    if (!(mask & (1u << kind))) {
        store_unlock();
        const char* why = (state == MW_LINK_STATE_WALLET)
                              ? "the device does not accept this file type"
                              : "no wallet is open on the device: unlock it and open a wallet";
        return reply_error(MW_LINK_ERR_LOCKED, why, out, cap);
    }

    if (g.inbox[kind].data) {
        store_unlock();
        return reply_error(MW_LINK_ERR_BUSY, "the previous file is still being processed",
                           out, cap);
    }
    mw_err_t e = slot_set(&g.inbox[kind], m->payload, m->len);
    if (e == MW_OK) g.seq++;
    store_unlock();
    if (e != MW_OK) return reply_error(MW_LINK_ERR_NO_MEMORY, "no memory for file", out, cap);

    fire_event();
    if (mw_link_msg_build(MW_LINK_RSP_ACK, kind, NULL, 0, out, cap, &n) != MW_OK) return 0;
    return n;
}

static size_t reply_req(const mw_link_msg_t* m, uint8_t* out, size_t cap) {
    size_t n = 0;
    if (m->arg != MW_LINK_REQ_ADDRESS && m->arg != MW_LINK_REQ_VIEWONLY)
        return reply_error(MW_LINK_ERR_BAD_CMD, "unknown request", out, cap);
    store_lock();
    if (g.state != MW_LINK_STATE_WALLET && g.state != MW_LINK_STATE_BUSY) {
        store_unlock();
        return reply_error(MW_LINK_ERR_LOCKED,
                           "no wallet is open on the device: unlock it and open a wallet",
                           out, cap);
    }
    const bool busy = g.request != 0;
    if (!busy) {
        g.request = m->arg;
        g.seq++;
    }
    store_unlock();
    if (busy) return reply_error(MW_LINK_ERR_BUSY, "a request is already pending", out, cap);
    fire_event();
    if (mw_link_msg_build(MW_LINK_RSP_ACK, m->arg, NULL, 0, out, cap, &n) != MW_OK) return 0;
    return n;
}

size_t mw_link_handle(const uint8_t* msg, size_t msg_len, uint8_t* out, size_t cap) {
    if (!out || cap < MW_LINK_OVERHEAD) return 0;
    if (!g.inited) return reply_error(MW_LINK_ERR_NOT_READY, "link not initialised", out, cap);

    mw_link_msg_t m;
    mw_err_t e = mw_link_msg_parse(msg, msg_len, &m);
    if (e != MW_OK) {
        switch (e) {
            case MW_ERR_MAGIC:    return reply_error(MW_LINK_ERR_BAD_MAGIC, "bad magic", out, cap);
            case MW_ERR_CHECKSUM: return reply_error(MW_LINK_ERR_CRC, "crc mismatch", out, cap);
            case MW_ERR_TOO_MANY: return reply_error(MW_LINK_ERR_TOO_BIG, "payload too large", out, cap);
            default:              return reply_error(MW_LINK_ERR_BAD_LEN, "length mismatch", out, cap);
        }
    }

    size_t n = 0;
    switch (m.cmd) {
    case MW_LINK_CMD_PING: {
        uint32_t len = m.len > MW_LINK_PING_MAX ? MW_LINK_PING_MAX : m.len;
        if (mw_link_msg_build(MW_LINK_RSP_PONG, m.arg, m.payload, len, out, cap, &n) != MW_OK)
            return reply_error(MW_LINK_ERR_NO_MEMORY, "reply buffer", out, cap);
        return n;
    }

    case MW_LINK_CMD_INFO:
        n = reply_info(out, cap);
        return n ? n : reply_error(MW_LINK_ERR_NO_MEMORY, "reply buffer", out, cap);

    case MW_LINK_CMD_STATUS:
        n = reply_status(out, cap);
        return n ? n : reply_error(MW_LINK_ERR_NO_MEMORY, "reply buffer", out, cap);

    case MW_LINK_CMD_PUT:
        return reply_put(&m, out, cap);

    case MW_LINK_CMD_REQ:
        return reply_req(&m, out, cap);

    case MW_LINK_CMD_GET: {
        if (!kind_ok(m.arg)) return reply_error(MW_LINK_ERR_BAD_KIND, "bad file kind", out, cap);
        store_lock();
        slot_t* s = &g.outbox[m.arg];
        if (!s->data) {
            store_unlock();
            return reply_error(MW_LINK_ERR_NOT_READY, "outbox empty", out, cap);
        }
        uint8_t* p = mw_link_msg_begin(MW_LINK_RSP_FILE, m.arg, (uint32_t)s->len, out, cap);
        if (!p) {
            store_unlock();
            return reply_error(MW_LINK_ERR_NO_MEMORY, "reply buffer", out, cap);
        }
        memcpy(p, s->data, s->len);
        n = mw_link_msg_finish(out, (uint32_t)s->len);
        store_unlock();
        return n;
    }

    case MW_LINK_CMD_CLEAR: {
        if (m.arg != MW_LINK_KIND_ALL && !kind_ok(m.arg))
            return reply_error(MW_LINK_ERR_BAD_KIND, "bad file kind", out, cap);
        store_lock();
        if (m.arg == MW_LINK_KIND_ALL) {
            for (int i = 0; i < MW_LINK_FILE_KINDS; ++i) slot_clear(&g.outbox[i]);
        } else {
            slot_clear(&g.outbox[m.arg]);
        }
        store_unlock();
        if (mw_link_msg_build(MW_LINK_RSP_ACK, m.arg, NULL, 0, out, cap, &n) != MW_OK) return 0;
        return n;
    }

    default:
        return reply_error(MW_LINK_ERR_BAD_CMD, "unknown command", out, cap);
    }
}

// ===========================================================================
// Names (diagnostics / host tool parity)
// ===========================================================================
const char* mw_link_cmd_name(uint8_t cmd) {
    switch (cmd) {
        case MW_LINK_CMD_PING:   return "PING";
        case MW_LINK_CMD_INFO:   return "INFO";
        case MW_LINK_CMD_PUT:    return "PUT";
        case MW_LINK_CMD_GET:    return "GET";
        case MW_LINK_CMD_STATUS: return "STATUS";
        case MW_LINK_CMD_CLEAR:  return "CLEAR";
        case MW_LINK_CMD_REQ:    return "REQ";
        case MW_LINK_EVT_LOG:    return "LOG";
        case MW_LINK_RSP_PONG:   return "PONG";
        case MW_LINK_RSP_INFO:   return "INFO";
        case MW_LINK_RSP_ACK:    return "ACK";
        case MW_LINK_RSP_FILE:   return "FILE";
        case MW_LINK_RSP_STATUS: return "STATUS";
        case MW_LINK_RSP_ERROR:  return "ERROR";
        default:                 return "?";
    }
}

const char* mw_link_err_name(uint8_t code) {
    switch (code) {
        case MW_LINK_ERR_BAD_CMD:   return "bad command";
        case MW_LINK_ERR_BAD_KIND:  return "bad file kind";
        case MW_LINK_ERR_TOO_BIG:   return "too big";
        case MW_LINK_ERR_NOT_READY: return "not ready";
        case MW_LINK_ERR_NO_MEMORY: return "no memory";
        case MW_LINK_ERR_CRC:       return "crc";
        case MW_LINK_ERR_BAD_LEN:   return "bad length";
        case MW_LINK_ERR_BAD_MAGIC: return "bad magic";
        case MW_LINK_ERR_BAD_FORMAT: return "unrecognised file";
        case MW_LINK_ERR_BUSY:      return "busy";
        case MW_LINK_ERR_LOCKED:    return "not accepted";
        default:                    return "?";
    }
}
