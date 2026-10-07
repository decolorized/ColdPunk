// Host-build stand-ins for the device-only entry points of the transfer layer.
//
// transfer.c is platform independent and is compiled into the host test runner,
// but the QR scanner's capture path (camera_scan.cpp, which needs a camera) is
// a C++ translation unit the host build never compiles, so its symbols are
// provided here instead. The USB link core (link.c) is plain C and needs no
// stub: the host tests drive it directly.
//
// SPDX-License-Identifier: MIT

#ifdef MW_HOST_BUILD

#include "transfer.h"
#include "qr_encode.h"

// ---------------------------------------------------------------------------
// QR scanning (camera_scan.cpp)
//
// The decoder itself is platform independent and does compile on the host; it
// is a .cpp file only because the pipeline reads better with a few small
// structs. Build camera_scan.cpp with -DMW_QR_SCAN_ON_HOST to link the real
// implementation instead of these stubs.
// ---------------------------------------------------------------------------

#ifndef MW_QR_SCAN_ON_HOST

mw_err_t mw_qr_scan_frame(const uint8_t* gray, uint16_t width, uint16_t height,
                          char* out, size_t out_cap) {
    (void)gray; (void)width; (void)height; (void)out; (void)out_cap;
    return MW_ERR_NOT_SUPPORTED;
}

mw_err_t mw_qr_scan_once(char* out, size_t out_cap) {
    (void)out; (void)out_cap;
    return MW_ERR_NOT_SUPPORTED;
}

// The device decoder allocates its working set from PSRAM on the first frame;
// there is nothing to release here.
void mw_qr_scan_release(void) { }

#endif /* !MW_QR_SCAN_ON_HOST */

#endif /* MW_HOST_BUILD */
