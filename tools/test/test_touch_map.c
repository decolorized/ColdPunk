// Touch coordinate pipeline (src/hal/touch_map.c), v5 bug 6.
//
// The panel model is Arduino_GFX's ILI9341 rotation table (MADCTL rot0 MX,
// rot1 MV, rot2 MY, rot3 MX|MY|MV), with the glass glued so that the raw
// touch point equals the logical point at rotation 0. ESPHome's ES3C28P
// configuration gives the same answer for rotations 1 and 3 on hardware.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"
#include "hal/touch_map.h"

#include <string.h>

#define MV 0x20
#define MX 0x40
#define MY 0x80
static const uint8_t MADCTL[4] = { MX, MV, MY, MX | MY | MV };

// Logical pixel -> GRAM (col,row) under MADCTL, then GRAM -> raw touch.
static void model_raw(int w0, int h0, int rot, int x, int y, int* rx, int* ry)
{
    const uint8_t m = MADCTL[rot & 3];
    int c, r;
    if (m & MV) { c = y; r = x; } else { c = x; r = y; }
    if (m & MX) c = w0 - 1 - c;
    if (m & MY) r = h0 - 1 - r;
    *rx = w0 - 1 - c;               // rotation 0 (MX) must be the identity
    *ry = r;
}

static mw_touch_geom_t geom(int w0, int h0, int rot)
{
    mw_touch_geom_t g;
    memset(&g, 0, sizeof g);
    g.native_w = (uint16_t)w0;
    g.native_h = (uint16_t)h0;
    g.rotation = (uint8_t)rot;
    return g;
}

// Every logical pixel of every rotation maps back exactly. Returns the
// number of mismatches.
static long sweep(int w0, int h0, int rot, const mw_touch_geom_t* g,
                  void (*glass)(int w0, int h0, int* rx, int* ry))
{
    const int lw = (rot & 1) ? h0 : w0, lh = (rot & 1) ? w0 : h0;
    long bad = 0;
    for (int y = 0; y < lh; ++y) {
        for (int x = 0; x < lw; ++x) {
            int rx, ry;
            uint16_t ox, oy;
            model_raw(w0, h0, rot, x, y, &rx, &ry);
            if (glass) glass(w0, h0, &rx, &ry);
            mw_touch_map_point(g, rx, ry, &ox, &oy);
            if (ox != x || oy != y) ++bad;
        }
    }
    return bad;
}

MW_TEST(test_rotations_round_trip)
{
    static const int sizes[][2] = { { 240, 320 }, { 240, 240 }, { 480, 480 },
                                    { 320, 480 } };
    for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; ++s) {
        for (int rot = 0; rot < 4; ++rot) {
            mw_touch_geom_t g = geom(sizes[s][0], sizes[s][1], rot);
            CHECK_EQ_INT(sweep(sizes[s][0], sizes[s][1], rot, &g, NULL), 0);
        }
    }
}

MW_TEST(test_logical_size)
{
    mw_touch_geom_t g = geom(240, 320, 1);
    CHECK_EQ_INT(mw_touch_logical_w(&g), 320);
    CHECK_EQ_INT(mw_touch_logical_h(&g), 240);
    g.rotation = 2;
    CHECK_EQ_INT(mw_touch_logical_w(&g), 240);
    CHECK_EQ_INT(mw_touch_logical_h(&g), 320);
}

MW_TEST(test_esphome_vectors)
{
    // touchpanel.yaml, USB left (MADCTL MV): swap_xy + mirror_y, i.e. the
    // glass reports raw (239 - y, x) for logical (x, y) in rotation 1.
    mw_touch_geom_t g1 = geom(240, 320, 1);
    // USB right (MV|MX|MY): swap_xy + mirror_x, raw (y, 319 - x), rotation 3.
    mw_touch_geom_t g3 = geom(240, 320, 3);
    static const int pts[][2] = { { 0, 0 }, { 319, 239 }, { 12, 12 },
                                  { 307, 227 }, { 160, 120 }, { 40, 200 } };
    for (unsigned i = 0; i < sizeof pts / sizeof pts[0]; ++i) {
        const int x = pts[i][0], y = pts[i][1];
        uint16_t ox, oy;
        mw_touch_map_point(&g1, 239 - y, x, &ox, &oy);
        CHECK_EQ_INT(ox, x);
        CHECK_EQ_INT(oy, y);
        mw_touch_map_point(&g3, y, 319 - x, &ox, &oy);
        CHECK_EQ_INT(ox, x);
        CHECK_EQ_INT(oy, y);
    }
}

// Synthetic glasses that differ from the panel; the board flags undo them.
static void glass_mirror_x(int w0, int h0, int* rx, int* ry)
{ (void)h0; (void)ry; *rx = w0 - 1 - *rx; }
static void glass_mirror_y(int w0, int h0, int* rx, int* ry)
{ (void)w0; (void)rx; *ry = h0 - 1 - *ry; }
static void glass_swap(int w0, int h0, int* rx, int* ry)
{ (void)w0; (void)h0; int t = *rx; *rx = *ry; *ry = t; }
// The flags apply swap first, then the mirrors: this glass is their inverse.
static void glass_swap_mirror_x(int w0, int h0, int* rx, int* ry)
{ glass_mirror_x(w0, h0, rx, ry); glass_swap(w0, h0, rx, ry); }

MW_TEST(test_mirror_and_swap_flags)
{
    for (int rot = 0; rot < 4; ++rot) {
        mw_touch_geom_t g = geom(240, 320, rot);
        g.mirror_x = true;
        CHECK_EQ_INT(sweep(240, 320, rot, &g, glass_mirror_x), 0);
        g = geom(240, 320, rot);
        g.mirror_y = true;
        CHECK_EQ_INT(sweep(240, 320, rot, &g, glass_mirror_y), 0);
        g = geom(240, 240, rot);
        g.swap_xy = true;
        CHECK_EQ_INT(sweep(240, 240, rot, &g, glass_swap), 0);
        g = geom(480, 480, rot);
        g.swap_xy = true;
        g.mirror_x = true;
        CHECK_EQ_INT(sweep(480, 480, rot, &g, glass_swap_mirror_x), 0);
    }
    // Without the flag the mirrored glass is wrong (the test can fail).
    mw_touch_geom_t g = geom(240, 320, 1);
    CHECK(sweep(240, 320, 1, &g, glass_mirror_x) > 0);
}

MW_TEST(test_clamp)
{
    mw_touch_geom_t g = geom(240, 320, 1);
    uint16_t x, y;
    mw_touch_map_point(&g, 4000, 4000, &x, &y);   // past the glass
    CHECK(x <= 319);
    CHECK(y <= 239);
    mw_touch_map_point(&g, -5, -5, &x, &y);
    CHECK(x <= 319);
    CHECK(y <= 239);
    CHECK_EQ_INT(x, 0);
    CHECK_EQ_INT(y, 239);
}

MW_TEST(test_calibration_solve_and_check)
{
    // XPT2046-like ADC: x = (u - 200) * 320 / 3700, y = (v - 200) * 480 / 3700.
    const int32_t tx[4] = { 48, 272, 48, 160 };
    const int32_t ty[4] = { 72, 72, 408, 240 };
    int32_t u[4], v[4], c[6];
    for (int i = 0; i < 4; ++i) {
        u[i] = 200 + tx[i] * 3700 / 320;
        v[i] = 200 + ty[i] * 3700 / 480;
    }
    CHECK_EQ_INT(mw_touch_cal_solve(u, v, tx, ty, c), 0);
    CHECK(mw_touch_cal_error(c, u[3], v[3], tx[3], ty[3]) <= 1);

    uint16_t x, y;
    mw_touch_cal_apply(c, u[3], v[3], 320, 480, &x, &y);
    CHECK(x >= 159 && x <= 161);
    CHECK(y >= 239 && y <= 241);

    // A sloppy third tap: the centre check is far off and gets rejected.
    int32_t v_bad[3] = { v[0], v[1], v[2] - 400 };
    CHECK_EQ_INT(mw_touch_cal_solve(u, v_bad, tx, ty, c), 0);
    CHECK(mw_touch_cal_error(c, u[3], v[3], tx[3], ty[3]) > MW_TOUCH_CAL_MAX_ERR_PX);

    // Collinear taps cannot be solved.
    const int32_t uc[3] = { 100, 200, 300 }, vc[3] = { 100, 200, 300 };
    CHECK_EQ_INT(mw_touch_cal_solve(uc, vc, tx, ty, c), -1);

    // The matrix an old landscape calibration stored (it absorbed the
    // rotation) is far off once the rotation map is in place.
    const int32_t rot90[6] = { 0, 65536, 0, -65536, 0, 15663104 };
    CHECK(mw_touch_cal_error(rot90, 40, 200, 40, 200) > MW_TOUCH_CAL_MAX_ERR_PX);
}

MW_TEST(test_calibration_tag)
{
    uint8_t t[3];
    mw_touch_cal_tag_make(t, 1, 320, 240);
    CHECK_EQ_INT(t[0], 0x80 | (1 << 2) | MW_TOUCH_MAP_VERSION);
    CHECK_EQ_INT(t[1], 40);
    CHECK_EQ_INT(t[2], 30);
    CHECK(mw_touch_cal_tag_ok(t, 1, 320, 240));
    CHECK(!mw_touch_cal_tag_ok(t, 3, 320, 240));          // other rotation
    CHECK(!mw_touch_cal_tag_ok(t, 0, 240, 320));          // portrait
    CHECK(!mw_touch_cal_tag_ok(t, 1, 480, 320));          // other panel

    // A tag from another map version is dropped.
    uint8_t old[3] = { (uint8_t)(0x80 | (1 << 2) | ((MW_TOUCH_MAP_VERSION + 1) & 3)), 40, 30 };
    CHECK(!mw_touch_cal_tag_ok(old, 1, 320, 240));

    // Untagged (pre-tag firmware) records: accepted only at rotation 0.
    const uint8_t none[3] = { 0, 0, 0 };
    CHECK(mw_touch_cal_tag_ok(none, 0, 320, 480));
    CHECK(mw_touch_cal_tag_ok(none, 0, 240, 320));
    CHECK(!mw_touch_cal_tag_ok(none, 1, 320, 240));
    CHECK(!mw_touch_cal_tag_ok(none, 2, 240, 320));

    mw_touch_cal_tag_make(t, 0, 480, 480);
    CHECK_EQ_INT(t[1], 60);
    CHECK(mw_touch_cal_tag_ok(t, 0, 480, 480));
}

int main(void)
{
    RUN_TEST(test_rotations_round_trip);
    RUN_TEST(test_logical_size);
    RUN_TEST(test_esphome_vectors);
    RUN_TEST(test_mirror_and_swap_flags);
    RUN_TEST(test_clamp);
    RUN_TEST(test_calibration_solve_and_check);
    RUN_TEST(test_calibration_tag);
    return mw_test_summary();
}
