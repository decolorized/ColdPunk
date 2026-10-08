// Touch controllers of TZ 2.4: FT6336G, FT6236, CST816S, GT911 (I2C) and
// XPT2046 (SPI).
//
// Capacitive controllers report pixels in the glass's own (rotation 0) axes.
// They go through the fixed map of touch_map.h: board fix-ups
// (TOUCH_SWAP_XY, TOUCH_MIRROR_X/Y), then DISPLAY_ROTATION.  They never apply
// a stored calibration: a matrix taken under another rotation or an older
// map would rotate the input a second time.
//
// The resistive XPT2046 reports ADC counts and uses a 3-point affine
// calibration, six Q16.16 coefficients:
//
//     x = (c0*u + c1*v + c2) >> 16
//     y = (c3*u + c4*v + c5) >> 16
//
// stored in mw_settings_t::touch_calib with a geometry tag (rotation, logical
// size, map version) in touch_cal_tag.  A record whose tag does not match the
// running geometry is dropped at boot.
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#include "display_drivers.h"
#include "log.h"
#include "touch_map.h"
#include "../wallet/secure_storage.h"

// ===========================================================================
// No touch panel: every entry point fails cleanly (TZ 2.5 button-only boards)
// ===========================================================================
#if !HAS_TOUCH || (TOUCH_DRIVER == TOUCH_NONE)

mw_err_t mw_touch_init(void)                  { return MW_ERR_NOT_SUPPORTED; }
bool     mw_touch_read(mw_touch_state_t* out)
{
    if (out) { out->pressed = false; out->x = 0; out->y = 0; }
    return false;
}
mw_err_t mw_touch_calibrate(int32_t coeffs[6]) { (void)coeffs;
                                                 return MW_ERR_NOT_SUPPORTED; }

#else   // ================= a touch panel is fitted =========================

#if TOUCH_DRIVER == TOUCH_XPT2046
#include <SPI.h>
#else
#include <Wire.h>
#endif

#define MW_Q16 65536

static int32_t s_cal[6];
static bool    s_ready = false;

#if TOUCH_DRIVER != TOUCH_XPT2046
static const mw_touch_geom_t s_geom = {
    (uint16_t)TOUCH_NATIVE_W, (uint16_t)TOUCH_NATIVE_H,
    (uint8_t)(DISPLAY_ROTATION & 3),
    TOUCH_SWAP_XY != 0, TOUCH_MIRROR_X != 0, TOUCH_MIRROR_Y != 0
};
static_assert(TOUCH_NATIVE_W > 0 && TOUCH_NATIVE_H > 0,
              "TOUCH_NATIVE_W/H must be the glass size at rotation 0");
#endif

static const char* driver_name(void)
{
#if   TOUCH_DRIVER == TOUCH_FT6336G
    return "FT6336G";
#elif TOUCH_DRIVER == TOUCH_FT6236
    return "FT6236";
#elif TOUCH_DRIVER == TOUCH_CST816S
    return "CST816S";
#elif TOUCH_DRIVER == TOUCH_GT911
    return "GT911";
#else
    return "XPT2046";
#endif
}

// --------------------------------------------------------------------------
// Default (uncalibrated) map of the resistive XPT2046
// --------------------------------------------------------------------------
// It reports 12-bit ADC counts and is unusable until calibrated - the values
// below only keep it roughly sane so the calibration screen itself can be hit.
static void cal_defaults(void)
{
#if TOUCH_DRIVER == TOUCH_XPT2046
    const int32_t raw_lo = 200, raw_hi = 3900;
    const int32_t span   = raw_hi - raw_lo;
    int32_t sx = (int32_t)(((int64_t)mw_display_width()  * MW_Q16) / span);
    int32_t sy = (int32_t)(((int64_t)mw_display_height() * MW_Q16) / span);
#if TOUCH_SWAP_XY
    s_cal[0] = 0;  s_cal[1] = sx; s_cal[2] = -sx * raw_lo;
    s_cal[3] = sy; s_cal[4] = 0;  s_cal[5] = -sy * raw_lo;
#else
    s_cal[0] = sx; s_cal[1] = 0;  s_cal[2] = -sx * raw_lo;
    s_cal[3] = 0;  s_cal[4] = sy; s_cal[5] = -sy * raw_lo;
#endif
#else   // capacitive: unused, the fixed map of touch_map.h applies
    s_cal[0] = MW_Q16; s_cal[1] = 0;      s_cal[2] = 0;
    s_cal[3] = 0;      s_cal[4] = MW_Q16; s_cal[5] = 0;
#endif
}

// Raw controller units -> logical screen point.
static void to_screen(int32_t u, int32_t v, uint16_t* x, uint16_t* y)
{
#if TOUCH_DRIVER == TOUCH_XPT2046
    mw_touch_cal_apply(s_cal, u, v, mw_display_width(), mw_display_height(), x, y);
#else
    mw_touch_map_point(&s_geom, u, v, x, y);
#endif
}

// ===========================================================================
// Per-controller raw read.  Each returns true when a finger is down and fills
// (*u, *v) with the controller's own units.
// ===========================================================================
#if TOUCH_DRIVER != TOUCH_XPT2046

#if TOUCH_DRIVER != TOUCH_GT911
static bool i2c_rd(uint8_t addr, uint8_t reg, uint8_t* buf, size_t len)
{
    Wire.beginTransmission(addr);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0) return false;   // repeated start
    // The (int, int) overload is the unambiguous one across core 2.x and 3.x.
    if ((size_t)Wire.requestFrom((int)addr, (int)len) != len) return false;
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)Wire.read();
    return true;
}
#endif

#if TOUCH_DRIVER == TOUCH_GT911
static uint8_t s_gt911_addr = 0x5D;

static bool gt911_rd(uint16_t reg, uint8_t* buf, size_t len)
{
    Wire.beginTransmission(s_gt911_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    if (Wire.endTransmission(false) != 0) return false;
    if ((size_t)Wire.requestFrom((int)s_gt911_addr, (int)len) != len) return false;
    for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)Wire.read();
    return true;
}

static bool gt911_wr8(uint16_t reg, uint8_t val)
{
    Wire.beginTransmission(s_gt911_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    Wire.write(val);
    return Wire.endTransmission() == 0;
}
#endif  // GT911

static bool raw_read(int32_t* u, int32_t* v)
{
#if (TOUCH_DRIVER == TOUCH_FT6336G) || (TOUCH_DRIVER == TOUCH_FT6236) || \
    (TOUCH_DRIVER == TOUCH_CST816S)
    // FT6x36 and CST816S share the register map: 0x02 = contact count, then
    // XH/XL/YH/YL with the coordinate in the low 12 bits.
#if TOUCH_DRIVER == TOUCH_CST816S
    const uint8_t addr = 0x15;
#else
    const uint8_t addr = 0x38;
#endif
    uint8_t b[5];
    if (!i2c_rd(addr, 0x02, b, sizeof(b))) return false;
    if ((b[0] & 0x0F) == 0) return false;               // no contact
    // P1_XH bits 7:6 = event flag: 0 press down, 1 lift up, 2 contact,
    // 3 no event.  After the finger leaves, both chips may keep reporting
    // one contact with the "lift up" flag (and the old coordinates) for a
    // while.  Counting that as a press hides the release from LVGL: the next
    // tap is then glued onto the previous press, and LVGL - which clicks the
    // object the press STARTED on - fires the wrong button or none at all
    // ("works only on the second tap").
    const uint8_t ev = (uint8_t)(b[1] >> 6);
    if (ev == 1 || ev == 3) return false;               // lifted / stale
    *u = (int32_t)(((uint16_t)(b[1] & 0x0F) << 8) | b[2]);
    *v = (int32_t)(((uint16_t)(b[3] & 0x0F) << 8) | b[4]);
    return true;

#elif TOUCH_DRIVER == TOUCH_GT911
    // 0x814E: bit7 = coordinates ready, bits3:0 = contact count.  The status
    // byte must be cleared by the host or the controller stops updating.
    uint8_t st = 0;
    if (!gt911_rd(0x814E, &st, 1)) return false;
    if ((st & 0x80) == 0) return false;
    uint8_t n = st & 0x0F;
    bool ok = false;
    if (n >= 1) {
        uint8_t p[8];                                   // one contact record
        if (gt911_rd(0x8150, p, sizeof(p))) {
            *u = (int32_t)(((uint16_t)p[2] << 8) | p[1]);
            *v = (int32_t)(((uint16_t)p[4] << 8) | p[3]);
            ok = true;
        }
    }
    gt911_wr8(0x814E, 0x00);                            // ack, always
    return ok;
#else
#error "TOUCH_DRIVER is not one of the TZ 2.4 controllers"
#endif
}

static mw_err_t bus_init(void)
{
    if (TOUCH_RST >= 0) {
        pinMode(TOUCH_RST, OUTPUT);
        digitalWrite(TOUCH_RST, LOW);
        delay(10);
        digitalWrite(TOUCH_RST, HIGH);
        delay(60);                       // GT911 needs >50 ms after reset
    }
    if (TOUCH_INT >= 0) pinMode(TOUCH_INT, INPUT);

    if (!Wire.begin(TOUCH_SDA, TOUCH_SCL, TOUCH_I2C_HZ)) return MW_ERR_IO;

#if TOUCH_DRIVER == TOUCH_GT911
    // The 7-bit address is latched from INT during reset; probe both.
    const uint8_t candidates[2] = { 0x5D, 0x14 };
    for (int i = 0; i < 2; ++i) {
        Wire.beginTransmission(candidates[i]);
        if (Wire.endTransmission() == 0) { s_gt911_addr = candidates[i];
                                           return MW_OK; }
    }
    return MW_ERR_IO;
#else
#if TOUCH_DRIVER == TOUCH_CST816S
    const uint8_t addr = 0x15;
#else
    const uint8_t addr = 0x38;
#endif
    Wire.beginTransmission(addr);
    return (Wire.endTransmission() == 0) ? MW_OK : MW_ERR_IO;
#endif
}

#else   // ================= XPT2046 over SPI ================================

// 12-bit resistive ADC.  A2A1A0 = 101 -> X, 001 -> Y, PD = 00 (reference on
// between conversions) so consecutive reads settle.
#define XPT_CMD_X 0xD0
#define XPT_CMD_Y 0x90
#ifndef TOUCH_SPI_HZ
#define TOUCH_SPI_HZ 2000000UL           // the part tops out around 2.5 MHz
#endif

static uint16_t xpt_xfer(uint8_t cmd)
{
    SPI.transfer(cmd);
    uint8_t hi = SPI.transfer(0x00);
    uint8_t lo = SPI.transfer(0x00);
    return (uint16_t)(((uint16_t)hi << 8 | lo) >> 3);    // 12 significant bits
}

static int cmp_u16(const void* a, const void* b)
{
    uint16_t x = *(const uint16_t*)a, y = *(const uint16_t*)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static bool raw_read(int32_t* u, int32_t* v)
{
    // The PENIRQ line is the only cheap "is a finger down" signal; without it
    // the ADC returns noise that looks like a touch near the rails.
    if (TOUCH_INT >= 0 && digitalRead(TOUCH_INT) != LOW) return false;

    uint16_t xs[7], ys[7];
    SPI.beginTransaction(SPISettings(TOUCH_SPI_HZ, MSBFIRST, SPI_MODE0));
    digitalWrite(TOUCH_CS, LOW);
    for (int i = 0; i < 7; ++i) { xs[i] = xpt_xfer(XPT_CMD_X);
                                  ys[i] = xpt_xfer(XPT_CMD_Y); }
    digitalWrite(TOUCH_CS, HIGH);
    SPI.endTransaction();

    // Median of seven: one spike from bus crosstalk cannot move it.
    qsort(xs, 7, sizeof(xs[0]), cmp_u16);
    qsort(ys, 7, sizeof(ys[0]), cmp_u16);
    uint16_t x = xs[3], y = ys[3];

    if (x < 64 || x > 4032 || y < 64 || y > 4032) return false;  // rail noise
    *u = (int32_t)x;
    *v = (int32_t)y;
    return true;
}

static mw_err_t bus_init(void)
{
    if (TOUCH_CS < 0) return MW_ERR_INVALID_ARG;
#if TFT_SCK < 0
#error "XPT2046 needs an SPI bus: define TFT_SCK/TFT_MOSI/TFT_MISO"
#endif
    pinMode(TOUCH_CS, OUTPUT);
    digitalWrite(TOUCH_CS, HIGH);       // released before anything else talks
    if (TOUCH_INT >= 0) pinMode(TOUCH_INT, INPUT_PULLUP);
    // The controller rides the display SPI bus.  mw_hal_init() brings the
    // display up first, so SPI.begin() has already run with the right pins;
    // every access below is wrapped in beginTransaction()/endTransaction() so
    // the 2 MHz XPT2046 clock cannot leak into the 40 MHz panel transfers.
    SPI.begin(TFT_SCK, TFT_MISO, TFT_MOSI, -1);
    return MW_OK;
}

#endif  // TOUCH_DRIVER dispatch

// ===========================================================================
// Public API
// ===========================================================================
mw_err_t mw_touch_init(void)
{
    cal_defaults();

    const char* cal = "none";
    mw_settings_t st;
    if (mw_settings_load(&st) == MW_OK && st.touch_calibrated) {
#if TOUCH_DRIVER == TOUCH_XPT2046
        if (mw_touch_cal_tag_ok(st.touch_cal_tag, DISPLAY_ROTATION & 3,
                                mw_display_width(), mw_display_height())) {
            memcpy(s_cal, st.touch_calib, sizeof(s_cal));
            cal = "loaded";
        } else {
            cal = "dropped";             // other geometry; NVS left untouched
        }
#else
        cal = "ignored";                 // capacitive: fixed map only
#endif
    }
    mw_touch_set_needs_calibration(TOUCH_DRIVER == TOUCH_XPT2046);

    mw_err_t e = bus_init();
    s_ready = (e == MW_OK);

    // Geometry only, never a coordinate.
#if TOUCH_DRIVER == TOUCH_XPT2046
    MW_LOGI("touch", "%s rot=%d logical=%dx%d swap=%d cal=%s%s", driver_name(),
            (int)(DISPLAY_ROTATION & 3), (int)mw_display_width(), (int)mw_display_height(),
            (int)(TOUCH_SWAP_XY != 0), cal, s_ready ? "" : " (bus error)");
#else
    MW_LOGI("touch", "%s rot=%d native=%dx%d logical=%dx%d swap=%d mx=%d my=%d cal=%s%s",
            driver_name(), (int)(DISPLAY_ROTATION & 3),
            (int)TOUCH_NATIVE_W, (int)TOUCH_NATIVE_H,
            (int)mw_display_width(), (int)mw_display_height(), (int)(TOUCH_SWAP_XY != 0),
            (int)(TOUCH_MIRROR_X != 0), (int)(TOUCH_MIRROR_Y != 0), cal,
            s_ready ? "" : " (bus error)");
#endif
    return e;
}

bool mw_touch_read(mw_touch_state_t* out)
{
    if (!out) return false;
    out->pressed = false;
    out->x = 0;
    out->y = 0;
    if (!s_ready) return false;

    static int32_t s_u = 0, s_v = 0;     // last contact, for the debug view
    int32_t u = 0, v = 0;
    if (!raw_read(&u, &v)) {
        uint16_t x, y;
        to_screen(s_u, s_v, &x, &y);
        mw_touch_debug_note(s_u, s_v, x, y, false);
        return false;
    }
    s_u = u;
    s_v = v;
    to_screen(u, v, &out->x, &out->y);
    mw_touch_debug_note(u, v, out->x, out->y, true);
    out->pressed = true;
    return true;
}

// --------------------------------------------------------------------------
// Calibration (XPT2046 only)
// --------------------------------------------------------------------------
#if TOUCH_DRIVER != TOUCH_XPT2046

mw_err_t mw_touch_calibrate(int32_t coeffs[6])
{
    // A capacitive glass reports pixels; its orientation comes from the board
    // flags and is checked on the Settings touch-test page.
    (void)coeffs;
    return MW_ERR_NOT_SUPPORTED;
}

#else

// Draws the targets and waits for a clean press-and-release on each, then
// solves for the six coefficients and checks them on a 4th target.  It paints
// through mw_display_blit() rather than through the UI layer; the caller
// holds the UI lock, so LVGL neither polls the panel nor flushes meanwhile.
static void draw_target(int16_t cx, int16_t cy)
{
    static uint16_t block[16 * 16];
    for (int i = 0; i < 16 * 16; ++i) block[i] = 0xFFFF;

    int16_t x = (int16_t)(cx - 8), y = (int16_t)(cy - 8);
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    const int16_t W = (int16_t)mw_display_width(), H = (int16_t)mw_display_height();
    if (x + 16 > W) x = (int16_t)(W - 16);
    if (y + 16 > H) y = (int16_t)(H - 16);
    mw_display_blit(x, y, 16, 16, block);
    mw_display_flush();
}

// Blocks until a stable press is seen, then until the finger leaves.
// Returns false on the 30 s timeout so a dead panel cannot wedge the boot.
static bool wait_point(int32_t* u, int32_t* v)
{
    const uint32_t deadline = millis() + 30000u;
    int32_t acc_u = 0, acc_v = 0;
    int     n     = 0;

    while ((int32_t)(millis() - deadline) < 0) {
        int32_t ru, rv;
        if (raw_read(&ru, &rv)) {
            acc_u += ru; acc_v += rv; ++n;
            if (n >= 8) break;          // eight consistent samples
        } else {
            acc_u = acc_v = 0; n = 0;   // bounced: start over
        }
        delay(15);
    }
    if (n < 8) return false;

    *u = acc_u / n;
    *v = acc_v / n;

    // Drain the release so the next target is not triggered by the same tap.
    uint32_t idle = millis();
    while ((int32_t)(millis() - deadline) < 0) {
        int32_t ru, rv;
        if (raw_read(&ru, &rv)) idle = millis();
        else if (millis() - idle > 150u) break;
        delay(10);
    }
    return true;
}

mw_err_t mw_touch_calibrate(int32_t coeffs[6])
{
    if (!coeffs) return MW_ERR_INVALID_ARG;
    if (!s_ready) return MW_ERR_NOT_SUPPORTED;

    // Targets at 15 %/85 % of each axis: far enough apart for a well
    // conditioned system, far enough from the bezel to be reachable.  The
    // 4th (centre) target only verifies the result.
    const int32_t W = (int32_t)mw_display_width(), H = (int32_t)mw_display_height();
    const int32_t tx[4] = { W * 15 / 100, W * 85 / 100, W * 15 / 100, W / 2 };
    const int32_t ty[4] = { H * 15 / 100, H * 15 / 100, H * 85 / 100, H / 2 };

    int32_t u[4], v[4];
    for (int i = 0; i < 4; ++i) {
        mw_display_fill(0x0000);
        draw_target((int16_t)tx[i], (int16_t)ty[i]);
        if (!wait_point(&u[i], &v[i])) {
            mw_display_fill(0x0000);
            return MW_ERR_ABORTED;
        }
    }
    mw_display_fill(0x0000);

    int32_t c[6];
    if (mw_touch_cal_solve(u, v, tx, ty, c) != 0) return MW_ERR_RANGE;
    const int32_t err = mw_touch_cal_error(c, u[3], v[3], tx[3], ty[3]);
    if (err > MW_TOUCH_CAL_MAX_ERR_PX) {
        MW_LOGE("touch", "calibration rejected: check point off by %d px", (int)err);
        return MW_ERR_RANGE;
    }
    memcpy(coeffs, c, sizeof(c));
    memcpy(s_cal, c, sizeof(s_cal));

    // Persist with the geometry tag.  A storage failure is reported but the
    // coefficients stay live for this session.
    mw_settings_t st;
    if (mw_settings_load(&st) != MW_OK) return MW_ERR_IO;
    memcpy(st.touch_calib, s_cal, sizeof(st.touch_calib));
    st.touch_calibrated = true;
    mw_touch_cal_tag_make(st.touch_cal_tag, DISPLAY_ROTATION & 3,
                          mw_display_width(), mw_display_height());
    return mw_settings_save(&st);
}

#endif  // TOUCH_DRIVER == TOUCH_XPT2046

#endif  // HAS_TOUCH
#endif  // ARDUINO && !MW_HOST_BUILD
