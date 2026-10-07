// Button navigation of the keyboards (v6): short / long SELECT and BACK,
// arrow auto-repeat, the two-arrow layout chord, and cursor stepping that
// skips dead seed letters, in 2-D and in the four-button linear mode.
//
// SPDX-License-Identifier: MIT
#include "test_framework.h"
#include "ui/keyboard_nav.h"

#include <string.h>

static mw_kn_out_t ev(mw_kn_t* k, mw_button_t b, uint32_t hold, bool rel, uint32_t now) {
    return mw_kn_event(k, b, hold, rel, now);
}

MW_TEST(test_select_short_and_long)
{
    mw_kn_t k; mw_kn_reset(&k);
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 0, false, 1000).act, MW_KN_NONE);   // nothing on press
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 100, false, 1100).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 150, true, 1150).act, MW_KN_ACTIVATE);

    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 0, false, 2000).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 599, false, 2599).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 600, false, 2600).act, MW_KN_FINISH);
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 900, false, 2900).act, MW_KN_NONE);   // once
    CHECK_EQ_INT(ev(&k, MW_BTN_SELECT, 1000, true, 3000).act, MW_KN_NONE);   // no char
}

MW_TEST(test_back_short_and_long)
{
    mw_kn_t k; mw_kn_reset(&k);
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 0, false, 10).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 200, true, 210).act, MW_KN_BACKSPACE);
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 0, false, 500).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 700, false, 1200).act, MW_KN_CANCEL);
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 800, true, 1300).act, MW_KN_NONE);
    // A release without a press (the key was down when the screen opened).
    CHECK_EQ_INT(ev(&k, MW_BTN_BACK, 50, true, 1400).act, MW_KN_NONE);
}

MW_TEST(test_arrow_repeat)
{
    mw_kn_t k; mw_kn_reset(&k);
    mw_kn_out_t o = ev(&k, MW_BTN_RIGHT, 0, false, 0);
    CHECK_EQ_INT(o.act, MW_KN_MOVE);
    CHECK_EQ_INT(o.dir, MW_BTN_RIGHT);
    int moves = 1;
    for (uint32_t t = 10; t <= 1000; t += 10)
        if (ev(&k, MW_BTN_RIGHT, t, false, t).act == MW_KN_MOVE) moves++;
    // 0, then 500, 620, 740, 860, 980
    CHECK_EQ_INT(moves, 6);
    CHECK_EQ_INT(ev(&k, MW_BTN_RIGHT, 1010, true, 1010).act, MW_KN_NONE);
}

MW_TEST(test_two_arrows_switch_layout)
{
    mw_kn_t k; mw_kn_reset(&k);
    CHECK_EQ_INT(ev(&k, MW_BTN_UP, 0, false, 0).act, MW_KN_MOVE);
    mw_kn_out_t o = ev(&k, MW_BTN_DOWN, 0, false, 80);
    CHECK_EQ_INT(o.act, MW_KN_LAYOUT);
    CHECK(o.undo_move);
    // Neither arrow moves or repeats any more, releases do nothing.
    for (uint32_t t = 100; t < 2000; t += 50) {
        CHECK_EQ_INT(ev(&k, MW_BTN_UP, t, false, t).act, MW_KN_NONE);
        CHECK_EQ_INT(ev(&k, MW_BTN_DOWN, t - 80, false, t).act, MW_KN_NONE);
    }
    CHECK_EQ_INT(ev(&k, MW_BTN_UP, 2000, true, 2000).act, MW_KN_NONE);
    CHECK_EQ_INT(ev(&k, MW_BTN_DOWN, 1920, true, 2000).act, MW_KN_NONE);
    // Next press is an ordinary move again.
    CHECK_EQ_INT(ev(&k, MW_BTN_DOWN, 0, false, 3000).act, MW_KN_MOVE);
    CHECK_EQ_INT(ev(&k, MW_BTN_DOWN, 10, true, 3010).act, MW_KN_NONE);

    // A slow second arrow (the first one was already repeating): still a
    // layout switch, but nothing is taken back.
    CHECK_EQ_INT(ev(&k, MW_BTN_LEFT, 0, false, 5000).act, MW_KN_MOVE);
    (void)ev(&k, MW_BTN_LEFT, 600, false, 5600);
    o = ev(&k, MW_BTN_RIGHT, 0, false, 5700);
    CHECK_EQ_INT(o.act, MW_KN_LAYOUT);
    CHECK(!o.undo_move);
}

// ---------------------------------------------------------------------------
static const char* g_live;        // '1' live, '0' dead
static bool live_fn(int i, void* ctx) { (void)ctx; return g_live[i] == '1'; }

MW_TEST(test_linear_step_skips_dead_and_wraps)
{
    g_live = "1001011";
    CHECK_EQ_INT(mw_kn_linear_step(7, 0, 1, live_fn, NULL), 3);
    CHECK_EQ_INT(mw_kn_linear_step(7, 3, 1, live_fn, NULL), 5);
    CHECK_EQ_INT(mw_kn_linear_step(7, 6, 1, live_fn, NULL), 0);    // wraps
    CHECK_EQ_INT(mw_kn_linear_step(7, 0, -1, live_fn, NULL), 6);
    CHECK_EQ_INT(mw_kn_linear_step(7, 3, -1, live_fn, NULL), 0);
    g_live = "0001000";
    CHECK_EQ_INT(mw_kn_linear_step(7, 3, 1, live_fn, NULL), 3);    // only one
    CHECK_EQ_INT(mw_kn_linear_step(0, 0, 1, live_fn, NULL), -1);
}

MW_TEST(test_grid_step)
{
    // 6 x 5 grid, 28 cells (last row short).
    char live[29];
    memset(live, '1', 28); live[28] = 0;
    g_live = live;
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 0, MW_BTN_RIGHT, live_fn, NULL), 1);
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 5, MW_BTN_RIGHT, live_fn, NULL), 6);   // row end
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 27, MW_BTN_RIGHT, live_fn, NULL), 27);
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 2, MW_BTN_UP, live_fn, NULL), -1);     // leaves
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 23, MW_BTN_DOWN, live_fn, NULL), 27);  // short row
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 26, MW_BTN_DOWN, live_fn, NULL), 26);

    // Dead letters are skipped.
    live[1] = live[2] = '0';
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 0, MW_BTN_RIGHT, live_fn, NULL), 3);
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 3, MW_BTN_LEFT, live_fn, NULL), 0);
    // Above a dead cell: the nearest live one in that row.
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 8, MW_BTN_UP, live_fn, NULL), 3);
    // A whole dead row is jumped over.
    for (int i = 6; i < 12; ++i) live[i] = '0';
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 14, MW_BTN_UP, live_fn, NULL), 3);
    CHECK_EQ_INT(mw_kn_grid_step(28, 6, 4, MW_BTN_DOWN, live_fn, NULL), 16);
}

int main(void)
{
    RUN_TEST(test_select_short_and_long);
    RUN_TEST(test_back_short_and_long);
    RUN_TEST(test_arrow_repeat);
    RUN_TEST(test_two_arrows_switch_layout);
    RUN_TEST(test_linear_step_skips_dead_and_wraps);
    RUN_TEST(test_grid_step);
    return mw_test_summary();
}
