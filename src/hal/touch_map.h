// Touch coordinate pipeline: panel fix-ups, display rotation, calibration
// solve/apply and the calibration geometry tag. Pure C, no board headers, so
// the host tests link it directly (test/test_touch_map.c).
//
// Pipeline for a capacitive controller (touch.cpp):
//   raw (rx, ry) in the glass's own axes
//   -> panel fix: TOUCH_SWAP_XY, then TOUCH_MIRROR_X / TOUCH_MIRROR_Y
//      (all in the unrotated panel space of native_w x native_h)
//   -> rotation by DISPLAY_ROTATION, matching Arduino_GFX's MADCTL table:
//        r0 (rx, ry)   r1 (ry, W0-1-rx)   r2 (W0-1-rx, H0-1-ry)   r3 (H0-1-ry, rx)
//   -> clamp to the logical screen.
// A resistive XPT2046 skips the map and goes through its stored affine
// calibration instead.
#ifndef MW_TOUCH_MAP_H
#define MW_TOUCH_MAP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bumped whenever the meaning of raw -> logical changes, so a calibration
// stored by an older pipeline is dropped instead of applied.
#define MW_TOUCH_MAP_VERSION 1

typedef struct {
    uint16_t native_w;     // glass/panel width with rotation 0
    uint16_t native_h;
    uint8_t  rotation;     // DISPLAY_ROTATION & 3
    bool     swap_xy;
    bool     mirror_x;
    bool     mirror_y;
} mw_touch_geom_t;

// Logical screen size for the geometry (odd rotations swap the axes).
uint16_t mw_touch_logical_w(const mw_touch_geom_t* g);
uint16_t mw_touch_logical_h(const mw_touch_geom_t* g);

// Raw controller point -> logical point, clamped to the logical screen.
void mw_touch_map_point(const mw_touch_geom_t* g, int32_t rx, int32_t ry,
                        uint16_t* x, uint16_t* y);

// Affine calibration, Q16.16: x = (c0*u + c1*v + c2) >> 16, y likewise.
// Result is clamped to w x h.
void mw_touch_cal_apply(const int32_t c[6], int32_t u, int32_t v,
                        uint16_t w, uint16_t h, uint16_t* x, uint16_t* y);

// Solves c from three raw points (u, v) and their targets (tx, ty).
// Returns 0 on success, -1 for collinear points or a coefficient overflow.
int mw_touch_cal_solve(const int32_t u[3], const int32_t v[3],
                       const int32_t tx[3], const int32_t ty[3], int32_t c[6]);

// Largest per-axis error, in pixels (unclamped), of c at raw (u, v) against
// the target (tx, ty). Used for the 4th verification target.
int32_t mw_touch_cal_error(const int32_t c[6], int32_t u, int32_t v,
                           int32_t tx, int32_t ty);
#define MW_TOUCH_CAL_MAX_ERR_PX 8

// Calibration geometry tag, stored in settings bytes 37..39:
//   tag[0] = 0x80 | (rotation & 3) << 2 | (MW_TOUCH_MAP_VERSION & 3)
//   tag[1] = width / 8, tag[2] = height / 8   (logical size)
void mw_touch_cal_tag_make(uint8_t tag[3], uint8_t rotation,
                           uint16_t width, uint16_t height);
// True when a stored calibration may be applied to this geometry. An
// untagged (all-zero) record is accepted only at rotation 0, the geometry
// every calibration before the tag was taken in.
bool mw_touch_cal_tag_ok(const uint8_t tag[3], uint8_t rotation,
                         uint16_t width, uint16_t height);

// ---------------------------------------------------------------------------
// Diagnostics, shared by touch.cpp (device) and the Settings touch-test page.
// Implemented in src/ui/lvgl_port.cpp, which every UI build links.
// ---------------------------------------------------------------------------
typedef struct {
    int32_t  raw_x, raw_y;     // controller units, before any mapping
    uint16_t x, y;             // logical screen point
    bool     pressed;
    bool     valid;            // false until the driver has reported once
} mw_touch_debug_t;

// Called by the driver on every read (pressed or not).
void mw_touch_debug_note(int32_t raw_x, int32_t raw_y, uint16_t x, uint16_t y,
                         bool pressed);
bool mw_touch_debug_last(mw_touch_debug_t* out);
// Coordinate trace (MW_LOGD on press/release edges). Coordinates on keyboard
// and PIN pages are keystrokes, so only the touch-test page turns it on; it
// is turned off when that page closes and on every lock request.
void mw_touch_trace(bool on);
bool mw_touch_trace_enabled(void);
// Set by the driver: true for a resistive panel that needs calibration.
void mw_touch_set_needs_calibration(bool on);
bool mw_touch_needs_calibration(void);

#ifdef __cplusplus
}
#endif
#endif
