// Self-contained QR Code generator (ISO/IEC 18004) for the wallet display,
// plus the animated-QR session API the UI pumps frames through.
//
// Byte mode only - every payload this wallet shows is an ASCII `ur:...` string
// or a Monero address. Versions 1..20, error-correction level L or M, full
// mask evaluation. No dynamic allocation: the caller owns the mw_qr_t bitmap.
//
// SPDX-License-Identifier: MIT
#ifndef MW_QR_ENCODE_H
#define MW_QR_ENCODE_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// QR code generation
// ---------------------------------------------------------------------------

#define MW_QR_MIN_VERSION 1
#define MW_QR_MAX_VERSION 20
#define MW_QR_MAX_SIZE    (17 + 4 * MW_QR_MAX_VERSION)      // 97 modules
#define MW_QR_STRIDE      ((MW_QR_MAX_SIZE + 7) / 8)        // 13 bytes per row

typedef enum {
    MW_QR_ECC_L = 0,     // ~7 % recovery  - denser, used for animated UR frames
    MW_QR_ECC_M = 1      // ~15 % recovery - used for static payloads
} mw_qr_ecc_t;

typedef struct {
    uint8_t     version;                              // 1..20
    uint8_t     size;                                 // 4*version + 17
    uint8_t     mask;                                 // 0..7, chosen by penalty
    mw_qr_ecc_t ecc;
    // Row-major bitmap, 1 bit per module, LSB-first within each byte.
    uint8_t     modules[MW_QR_MAX_SIZE * MW_QR_STRIDE];
} mw_qr_t;

// True when the module at (x, y) is dark. Out-of-range reads return false so a
// UI that draws a quiet zone can walk past the edges safely.
bool mw_qr_get(const mw_qr_t* q, int x, int y);

// Byte-mode payload capacity of one (version, ecc) pair, in bytes.
size_t mw_qr_byte_capacity(uint8_t version, mw_qr_ecc_t ecc);

// Smallest version that fits `len` bytes at `ecc`, or 0 if it does not fit.
uint8_t mw_qr_min_version(size_t len, mw_qr_ecc_t ecc);

// Encodes into the smallest version that fits.
mw_err_t mw_qr_encode(const uint8_t* data, size_t len, mw_qr_ecc_t ecc,
                      mw_qr_t* out);

// Encodes at exactly `version` (so an animated sequence keeps one module size
// on screen even when the frames differ slightly in length).
mw_err_t mw_qr_encode_version(const uint8_t* data, size_t len, mw_qr_ecc_t ecc,
                              uint8_t version, mw_qr_t* out);

// Convenience wrapper for NUL-terminated payloads (UR strings, addresses).
mw_err_t mw_qr_encode_text(const char* text, mw_qr_ecc_t ecc, mw_qr_t* out);

// ---- shared with the scanner (camera_scan.cpp) ----------------------------
// The decoder needs the same tables and geometry the encoder uses; exposing
// them here keeps a single source of truth instead of two drifting copies.

// Data-masking pattern of clause 7.8.2: true where the module is inverted.
bool mw_qr_mask_bit(uint8_t mask, int x, int y);

// Marks every function module (finder, separator, timing, alignment, format,
// version, dark module) of `version` in a MW_QR_MAX_SIZE * MW_QR_STRIDE bitmap.
mw_err_t mw_qr_function_map(uint8_t version, uint8_t* out, size_t cap);

// Block layout of one (version, ecc): total codewords, data codewords, the
// number of error-correction blocks and the EC codewords per block.
mw_err_t mw_qr_block_layout(uint8_t version, mw_qr_ecc_t ecc,
                            uint16_t* total_cw, uint16_t* data_cw,
                            uint8_t* num_blocks, uint8_t* ecc_len);

// Reads bit `index` of the bitmap used by mw_qr_t and mw_qr_function_map.
bool mw_qr_bitmap_get(const uint8_t* bitmap, int x, int y);
void mw_qr_bitmap_set(uint8_t* bitmap, int x, int y, bool dark);

// ---------------------------------------------------------------------------
// Animated-QR session (TZ 3.7)
//
// Implemented in transfer/transfer.c and transfer/camera_scan.cpp. Declared
// here because transfer.h is a frozen contract; docs/qr_protocol.md carries the
// full description of the flow for the UI layer.
// ---------------------------------------------------------------------------

// The UI hook is called once per frame while a QR transfer runs. `frame` is
// the symbol to draw (NULL while receiving), `permille` the progress. Returning
// false cancels the transfer, which then fails with MW_ERR_ABORTED.
typedef bool (*mw_qr_ui_hook_t)(const mw_qr_t* frame, int permille, void* ctx);
void mw_qr_set_ui_hook(mw_qr_ui_hook_t hook, void* ctx);

// Error-correction level and fragment size used for animated frames (TZ 3.7).
#define MW_QR_UR_ECC       MW_QR_ECC_L
#define MW_QR_FRAME_MS     80        // 12.5 FPS

// ---- outgoing: the device displays an animated UR sequence ----------------

// Starts an outgoing sequence over `buf` (which must stay valid until stop).
// `fragment` is the UR fragment size in bytes; 0 selects MW_UR_DEFAULT_FRAGMENT.
mw_err_t mw_qr_send_begin(const uint8_t* buf, size_t len, const char* ur_type,
                          size_t fragment);
// Renders the next frame of the sequence into `out`. Cycles forever.
mw_err_t mw_qr_send_next(mw_qr_t* out);
// Number of "pure" parts in the running sequence (1 == static QR).
uint32_t mw_qr_send_seq_len(void);
void     mw_qr_send_end(void);

// ---- incoming: the camera scans an animated UR sequence -------------------

mw_err_t mw_qr_recv_begin(uint8_t* buf, size_t cap);
// Feeds one decoded QR string. MW_OK == accepted, MW_ERR_FORMAT == ignore.
mw_err_t mw_qr_recv_feed(const char* text);
bool     mw_qr_recv_complete(void);
int      mw_qr_recv_progress_permille(void);
mw_err_t mw_qr_recv_result(const uint8_t** data, size_t* len);
void     mw_qr_recv_end(void);

// ---- camera plumbing (camera_scan.cpp) ------------------------------------
//
// The frame grabber itself is the HAL's (mw_camera_capture, hal.h); this layer
// only turns a grayscale frame into a decoded QR string.

#define MW_QR_SCAN_MAX_TEXT 4096

// Binarises and decodes one already-captured grayscale frame.
mw_err_t mw_qr_scan_frame(const uint8_t* gray, uint16_t width, uint16_t height,
                          char* out, size_t out_cap);
// Captures a frame through the HAL and decodes it. MW_ERR_FORMAT when the
// frame holds no readable code, MW_ERR_NOT_SUPPORTED without a camera.
mw_err_t mw_qr_scan_once(char* out, size_t out_cap);
// Frees the decoder's 67 KB PSRAM working set, which mw_qr_scan_frame()
// allocates on the first frame. Call it when the scanner screen closes; the
// next frame simply allocates again.
void     mw_qr_scan_release(void);

#ifdef __cplusplus
}
#endif
#endif
