// Unified data-exchange layer (TZ 3): channel dispatch over the SD card, the
// animated QR codec and the USB link, plus the canonical file names of TZ 9.
//
// A screen asks for "the next input file" and does not care which wire it
// arrives on. Each channel is a thin adapter:
//
//   MW_CHANNEL_SD        - sd_transfer.c, plain FAT reads and writes;
//   MW_CHANNEL_QR        - the UR fountain codec of ur.c driven frame by frame,
//                          with the UI hook owning the actual screen and camera;
//   MW_CHANNEL_USB_LINK  - the inbox/outbox of link.c, filled and drained by
//                          the host program over CDC serial or vendor HID.
//
// SPDX-License-Identifier: MIT

#include "transfer.h"
#include "ur.h"
#include "qr_encode.h"
#include "link.h"
#include "../hal/hal.h"

#include <string.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// Canonical file names (TZ 9)
// ---------------------------------------------------------------------------

const char* const MW_FILENAME[MW_FILE_KIND_COUNT] = {
    "outputs.bin",
    "keyimages.bin",
    "unsigned_tx_set.bin",
    "signed_tx_set.bin",
    "wallet_export.json",
};

// ---------------------------------------------------------------------------
// Implemented in sd_transfer.c. Declared here rather than in a shared header
// because transfer.h is a frozen contract.
// ---------------------------------------------------------------------------

mw_err_t    mw_sd_transfer_init(void);
bool        mw_sd_transfer_available(void);
const char* mw_sd_transfer_path(mw_file_kind_id_t kind);
mw_err_t    mw_sd_transfer_read(mw_file_kind_id_t kind, uint8_t* buf,
                                size_t cap, size_t* len);
mw_err_t    mw_sd_transfer_write(mw_file_kind_id_t kind, const uint8_t* buf,
                                 size_t len);

// ---------------------------------------------------------------------------
// QR session state
// ---------------------------------------------------------------------------

static struct {
    mw_qr_ui_hook_t hook;
    void*           ctx;

    // outgoing
    mw_ur_encoder*  enc;
    uint8_t         version;          // pinned so the module size never jumps
    bool            sending;

    // incoming
    mw_ur_decoder*  dec;
    bool            receiving;
} g_qr;

static mw_qr_t g_frame;               // ~1.3 KB, reused between frames

void mw_qr_set_ui_hook(mw_qr_ui_hook_t hook, void* ctx) {
    g_qr.hook = hook;
    g_qr.ctx = ctx;
}

// ---- outgoing --------------------------------------------------------------

void mw_qr_send_end(void) {
    if (g_qr.enc) { mw_ur_encoder_free(g_qr.enc); g_qr.enc = NULL; }
    g_qr.sending = false;
    g_qr.version = 0;
}

mw_err_t mw_qr_send_begin(const uint8_t* buf, size_t len, const char* ur_type,
                          size_t fragment) {
    if (!buf || len == 0 || len > MW_TRANSFER_MAX_FILE) return MW_ERR_INVALID_ARG;
    mw_qr_send_end();
    if (!ur_type) ur_type = MW_UR_TYPE_BYTES;
    if (fragment == 0) fragment = MW_UR_DEFAULT_FRAGMENT;

    g_qr.enc = mw_ur_encoder_new(ur_type, buf, len, fragment);
    if (!g_qr.enc) return MW_ERR_MEMORY;

    // Pin the QR version: render one frame, note the version it needs, and use
    // that for every frame of the sequence. Frames differ in length by a byte
    // or two (the seqNum digits), which would otherwise change the symbol size
    // mid-animation and force the scanner to re-acquire.
    char text[MW_QR_SCAN_MAX_TEXT];
    size_t n = mw_ur_encoder_next(g_qr.enc, text, sizeof text);
    if (n == 0) { mw_qr_send_end(); return MW_ERR_RANGE; }
    // Allow a few extra characters of headroom for a longer sequence number.
    uint8_t v = mw_qr_min_version(n + 4, MW_QR_UR_ECC);
    if (v == 0) { mw_qr_send_end(); return MW_ERR_TOO_MANY; }
    g_qr.version = v;
    g_qr.sending = true;
    return MW_OK;
}

uint32_t mw_qr_send_seq_len(void) {
    return g_qr.enc ? mw_ur_encoder_seq_len(g_qr.enc) : 0;
}

mw_err_t mw_qr_send_next(mw_qr_t* out) {
    if (!g_qr.sending || !g_qr.enc || !out) return MW_ERR_INVALID_ARG;
    char text[MW_QR_SCAN_MAX_TEXT];
    size_t n = mw_ur_encoder_next(g_qr.enc, text, sizeof text);
    if (n == 0) return MW_ERR_RANGE;
    mw_err_t err = mw_qr_encode_version((const uint8_t*)text, n, MW_QR_UR_ECC,
                                        g_qr.version, out);
    if (err == MW_ERR_TOO_MANY) {
        // The sequence number grew past the pinned version's capacity; step up
        // once rather than dropping the frame.
        uint8_t v = mw_qr_min_version(n, MW_QR_UR_ECC);
        if (v == 0) return MW_ERR_TOO_MANY;
        g_qr.version = v;
        err = mw_qr_encode_version((const uint8_t*)text, n, MW_QR_UR_ECC, v, out);
    }
    return err;
}

// ---- incoming --------------------------------------------------------------

void mw_qr_recv_end(void) {
    if (g_qr.dec) { mw_ur_decoder_free(g_qr.dec); g_qr.dec = NULL; }
    g_qr.receiving = false;
}

mw_err_t mw_qr_recv_begin(uint8_t* buf, size_t cap) {
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    mw_qr_recv_end();
    g_qr.dec = mw_ur_decoder_new(buf, cap);
    if (!g_qr.dec) return MW_ERR_MEMORY;
    g_qr.receiving = true;
    return MW_OK;
}

mw_err_t mw_qr_recv_feed(const char* text) {
    if (!g_qr.receiving || !g_qr.dec) return MW_ERR_INVALID_ARG;
    return mw_ur_decoder_receive(g_qr.dec, text);
}

bool mw_qr_recv_complete(void) {
    return g_qr.dec && mw_ur_decoder_complete(g_qr.dec);
}

int mw_qr_recv_progress_permille(void) {
    return g_qr.dec ? mw_ur_decoder_progress_permille(g_qr.dec) : 0;
}

mw_err_t mw_qr_recv_result(const uint8_t** data, size_t* len) {
    if (!g_qr.dec) return MW_ERR_INVALID_ARG;
    return mw_ur_decoder_result(g_qr.dec, data, len, NULL, 0);
}

// ---------------------------------------------------------------------------
// Blocking channel drivers used by mw_transfer_receive/send
// ---------------------------------------------------------------------------

static bool ui_frame(const mw_qr_t* frame, int permille) {
    if (!g_qr.hook) return true;           // headless: run to completion
    return g_qr.hook(frame, permille, g_qr.ctx);
}

static mw_err_t qr_receive(uint8_t* buf, size_t cap, size_t* len) {
    mw_err_t err = mw_qr_recv_begin(buf, cap);
    if (err != MW_OK) return err;

    err = mw_camera_init();
    if (err != MW_OK) { mw_qr_recv_end(); return err; }

    char text[MW_QR_SCAN_MAX_TEXT];
    mw_err_t result = MW_ERR_ABORTED;

    for (;;) {
        if (mw_qr_scan_once(text, sizeof text) == MW_OK)
            (void)mw_qr_recv_feed(text);           // junk frames are ignored

        int permille = mw_qr_recv_progress_permille();
        if (mw_qr_recv_complete()) {
            const uint8_t* data = NULL;
            size_t n = 0;
            result = mw_qr_recv_result(&data, &n);
            if (result == MW_OK) {
                // The decoder wrote into `buf`; `data` points inside it past
                // the CBOR head, so slide the payload down to the start.
                if (n > cap) { result = MW_ERR_TOO_MANY; }
                else {
                    if (data != buf) memmove(buf, data, n);
                    if (len) *len = n;
                }
            }
            (void)ui_frame(NULL, 1000);
            break;
        }
        if (!ui_frame(NULL, permille)) { result = MW_ERR_ABORTED; break; }
    }

    mw_camera_deinit();
    mw_qr_scan_release();
    mw_qr_recv_end();
    return result;
}

static mw_err_t qr_send(const uint8_t* buf, size_t len) {
    mw_err_t err = mw_qr_send_begin(buf, len, MW_UR_TYPE_BYTES,
                                    MW_UR_DEFAULT_FRAGMENT);
    if (err != MW_OK) return err;

    uint32_t seq_len = mw_qr_send_seq_len();
    uint32_t shown = 0;
    mw_err_t result = MW_OK;

    for (;;) {
        err = mw_qr_send_next(&g_frame);
        if (err != MW_OK) { result = err; break; }
        shown++;
        int permille = seq_len ? (int)((shown * 1000u) / seq_len) : 1000;
        if (permille > 1000) permille = 1000;
        if (!ui_frame(&g_frame, permille)) break;   // the user says it is done
        mw_delay_ms(MW_QR_FRAME_MS);
    }

    mw_qr_send_end();
    return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

mw_err_t mw_transfer_init(void) {
    memset(&g_qr, 0, sizeof g_qr);
    return mw_sd_transfer_init();
}

bool mw_transfer_available(mw_channel_t ch) {
    const mw_hal_caps_t* caps = mw_hal_caps();
    switch (ch) {
        case MW_CHANNEL_SD:
            return mw_sd_transfer_available();
        case MW_CHANNEL_QR:
            return caps && caps->has_camera;
        case MW_CHANNEL_USB_LINK:
            // Up once usb_link_arduino.cpp has brought a transport up. The host
            // program may or may not be running; that only shows when a file
            // is awaited, which is what the cancellable wait is for.
            return mw_link_is_up();
        case MW_CHANNEL_AUDIO:
        default:
            return false;
    }
}

mw_err_t mw_transfer_receive(mw_channel_t ch, mw_file_kind_id_t kind,
                             uint8_t* buf, size_t cap, size_t* len) {
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if ((unsigned)kind >= MW_FILE_KIND_COUNT) return MW_ERR_INVALID_ARG;
    if (cap > MW_TRANSFER_MAX_FILE) cap = MW_TRANSFER_MAX_FILE;
    if (len) *len = 0;

    switch (ch) {
        case MW_CHANNEL_SD:
            return mw_sd_transfer_read(kind, buf, cap, len);
        case MW_CHANNEL_QR:
            return qr_receive(buf, cap, len);
        case MW_CHANNEL_USB_LINK:
            // Blocks until the host PUTs a file of this kind; the wait hook
            // installed by the UI flow turns the progress page's Cancel into
            // MW_ERR_ABORTED.
            return mw_link_wait_inbox(kind, buf, cap, len, 0);
        default:
            return MW_ERR_NOT_SUPPORTED;
    }
}

mw_err_t mw_transfer_send(mw_channel_t ch, mw_file_kind_id_t kind,
                          const uint8_t* buf, size_t len) {
    if (!buf || len == 0) return MW_ERR_INVALID_ARG;
    if ((unsigned)kind >= MW_FILE_KIND_COUNT) return MW_ERR_INVALID_ARG;
    if (len > MW_TRANSFER_MAX_FILE) return MW_ERR_TOO_MANY;

    switch (ch) {
        case MW_CHANNEL_SD:
            return mw_sd_transfer_write(kind, buf, len);
        case MW_CHANNEL_QR:
            return qr_send(buf, len);
        case MW_CHANNEL_USB_LINK:
            // Parks the file in the outbox and returns at once; the host
            // fetches it with GET whenever it polls next. It stays there
            // until the host CLEARs it, so a dropped cable costs nothing.
            return mw_link_outbox_put(kind, buf, len);
        default:
            return MW_ERR_NOT_SUPPORTED;
    }
}
