// Minesweeper model (bug v5 #1): rules, input state machine, layout.
#include "test_framework.h"
#include "ui/game_model.h"
#include "crypto/random.h"

#include <string.h>

static void seed(uint32_t s) {
    static uint8_t buf[4];
    buf[0] = (uint8_t)s; buf[1] = (uint8_t)(s >> 8); buf[2] = (uint8_t)(s >> 16); buf[3] = (uint8_t)(s >> 24);
    mw_random_set_test_source(buf, sizeof buf);
}

static int lvgl_count(const char* const* map) {   // lv_buttonmatrix.c counting loop
    int n = 0;
    for (size_t j = 0; map[j] && map[j][0] != '\0'; j++) if (strcmp(map[j], "\n") != 0) n++;
    return n;
}

// The regression itself: the shipped screen put "" in every hidden cell, so
// LVGL counted zero buttons and the board was empty and dead.
MW_TEST(test_empty_text_truncates_lvgl_map) {
    const char* old_map[] = { "", "", "\n", "", "", "" };
    CHECK_EQ_INT(lvgl_count(old_map), 0);
    const char* mid_map[] = { "1", "", "\n", "", "2", "" };
    CHECK_EQ_INT(lvgl_count(mid_map), 1);
}

MW_TEST(test_map_has_every_cell_in_every_state) {
    static char text[MW_GAME_MAX_CELLS][4];
    static const char* map[MW_GAME_MAP_LEN];
    for (uint32_t s = 1; s <= 200; s++) {
        mw_game_t g;
        seed(s);
        mw_game_init(&g, 6 + (int)(s % 5), 4 + (int)(s % 9));
        CHECK_EQ_INT(mw_game_build_map(&g, text, map, MW_GAME_MAP_LEN), g.cells);   // fresh
        mw_game_toggle_flag(&g, 0);
        CHECK_EQ_INT(mw_game_build_map(&g, text, map, MW_GAME_MAP_LEN), g.cells);   // flagged
        mw_game_toggle_flag(&g, 0);
        mw_game_reveal(&g, (int)(s % (uint32_t)g.cells));
        CHECK_EQ_INT(mw_game_build_map(&g, text, map, MW_GAME_MAP_LEN), g.cells);   // opened
        if (g.state == MW_GAME_WON) {           // tiny board cleared by the first flood
            CHECK_EQ_INT(mw_game_build_map(&g, text, map, MW_GAME_MAP_LEN), g.cells);
            continue;
        }
        for (int i = 0; i < g.cells && g.state == MW_GAME_PLAY; i++)
            if (g.mine[i]) mw_game_reveal(&g, i);
        CHECK(g.state == MW_GAME_LOST);
        CHECK_EQ_INT(mw_game_build_map(&g, text, map, MW_GAME_MAP_LEN), g.cells);   // lost
        CHECK_EQ_INT(lvgl_count(map), g.cells);
        for (int i = 0; i < g.cells; i++) CHECK(text[i][0] != '\0');
    }
}

MW_TEST(test_first_reveal_is_safe_and_mines_exact) {
    for (uint32_t s = 1; s <= 300; s++) {
        mw_game_t g;
        seed(s * 7919u);
        mw_game_init(&g, 10, 6);
        const int first = (int)((s * 37u) % (uint32_t)g.cells);
        mw_game_reveal(&g, first);
        CHECK(g.placed);
        CHECK(g.state != MW_GAME_LOST);
        int n = 0;
        for (int i = 0; i < g.cells; i++) n += g.mine[i];
        CHECK_EQ_INT(n, g.mines);
        for (int dr = -1; dr <= 1; dr++)
            for (int dc = -1; dc <= 1; dc++) {
                const int r = first / g.cols + dr, c = first % g.cols + dc;
                if (r >= 0 && r < g.rows && c >= 0 && c < g.cols) CHECK(!g.mine[r * g.cols + c]);
            }
        CHECK_EQ_INT(g.adj[first], 0);   // so the first tap always opens an area
        CHECK(g.open[first]);
    }
}

MW_TEST(test_adjacency_and_flood) {
    mw_game_t g;
    seed(4242);
    mw_game_init(&g, 8, 8);
    mw_game_reveal(&g, 27);
    for (int i = 0; i < g.cells; i++) {
        int n = 0;
        for (int j = 0; j < g.cells; j++) {
            const int dr = j / g.cols - i / g.cols, dc = j % g.cols - i % g.cols;
            if (j != i && dr >= -1 && dr <= 1 && dc >= -1 && dc <= 1 && g.mine[j]) n++;
        }
        CHECK_EQ_INT(g.adj[i], n);
        // Flood invariant: an opened zero cell has all its neighbours opened.
        if (g.open[i] && g.adj[i] == 0 && !g.mine[i])
            for (int j = 0; j < g.cells; j++) {
                const int dr = j / g.cols - i / g.cols, dc = j % g.cols - i % g.cols;
                if (dr >= -1 && dr <= 1 && dc >= -1 && dc <= 1) CHECK(g.open[j]);
            }
        CHECK(!(g.open[i] && g.mine[i]));
    }
}

MW_TEST(test_flag_blocks_reveal_and_flood) {
    mw_game_t g;
    seed(99);
    mw_game_init(&g, 8, 8);
    mw_game_toggle_flag(&g, 63);
    CHECK_EQ_INT(mw_game_flags(&g), 1);
    mw_game_reveal(&g, 63);
    CHECK(!g.placed && !g.open[63]);            // a flagged cell is not revealed
    mw_game_reveal(&g, 0);
    CHECK(!g.open[63]);                         // flood stops at the flag
}

MW_TEST(test_win) {
    mw_game_t g;
    seed(7);
    mw_game_init(&g, 6, 4);
    mw_game_reveal(&g, 0);
    for (int i = 0; i < g.cells; i++) if (!g.mine[i]) mw_game_reveal(&g, i);
    CHECK(g.state == MW_GAME_WON);
    CHECK(!mw_game_unlock_tap(&g, 0, 0));       // winning never unlocks
}

static void lose(mw_game_t* g) {
    seed(1234);
    mw_game_init(g, 10, 6);
    mw_game_reveal(g, 0);
    for (int i = 0; i < g->cells; i++) if (g->mine[i]) { mw_game_reveal(g, i); break; }
}

MW_TEST(test_unlock_gesture) {
    mw_game_t g;
    lose(&g);
    CHECK(g.state == MW_GAME_LOST);
    const int ex = g.exploded;
    CHECK(ex >= 0 && g.mine[ex]);
    CHECK_EQ_INT(g.taps, 0);                    // the exploding tap does not count
    CHECK(!mw_game_unlock_tap(&g, ex, 10000));
    CHECK(!mw_game_unlock_tap(&g, ex, 10300));
    CHECK(mw_game_unlock_tap(&g, ex, 10600));
    // exactly at the window edge still counts, one ms later does not
    lose(&g);
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 1000));
    CHECK(mw_game_unlock_tap(&g, g.exploded, MW_GAME_UNLOCK_WINDOW_MS));
    lose(&g);
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 1000));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, MW_GAME_UNLOCK_WINDOW_MS + 1));   // restarts at 1
    // a tap elsewhere resets
    lose(&g);
    const int other = (g.exploded + 1) % g.cells;
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 100));
    CHECK(!mw_game_unlock_tap(&g, other, 200));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 300));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 400));
    CHECK(mw_game_unlock_tap(&g, g.exploded, 500));
    // a long press (reset) in the middle
    lose(&g);
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 100));
    mw_game_unlock_reset(&g);
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 200));
    // timer wrap-around
    lose(&g);
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0xFFFFFF00u));
    CHECK(!mw_game_unlock_tap(&g, g.exploded, 0xFFFFFFF0u));
    CHECK(mw_game_unlock_tap(&g, g.exploded, 0x00000100u));
    // never while playing
    mw_game_t p;
    seed(5);
    mw_game_init(&p, 8, 8);
    for (int k = 0; k < 5; k++) CHECK(!mw_game_unlock_tap(&p, 0, (uint32_t)k));
}

// ---- A3: flood fill against a reference BFS that marks on enqueue --------
static uint32_t lcg(uint32_t* s) { *s = *s * 1103515245u + 12345u; return *s >> 8; }

static void calc_adj(mw_game_t* g) {
    for (int i = 0; i < g->cells; i++) {
        int n = 0;
        const int r = i / g->cols, c = i % g->cols;
        for (int dr = -1; dr <= 1; dr++)
            for (int dc = -1; dc <= 1; dc++) {
                const int rr = r + dr, cc = c + dc;
                if ((dr || dc) && rr >= 0 && rr < g->rows && cc >= 0 && cc < g->cols &&
                    g->mine[rr * g->cols + cc]) n++;
            }
        g->adj[i] = (uint8_t)n;
    }
}

static int ref_flood(const mw_game_t* g, int s) {
    int q[MW_GAME_MAX_CELLS], h = 0, t = 0;
    bool seen[MW_GAME_MAX_CELLS] = { 0 };
    q[t++] = s; seen[s] = true;
    while (h < t) {
        const int i = q[h++];
        if (g->adj[i] || g->mine[i]) continue;
        const int r = i / g->cols, c = i % g->cols;
        for (int dr = -1; dr <= 1; dr++)
            for (int dc = -1; dc <= 1; dc++) {
                const int rr = r + dr, cc = c + dc;
                if (rr < 0 || rr >= g->rows || cc < 0 || cc >= g->cols) continue;
                const int j = rr * g->cols + cc;
                if (!seen[j]) { seen[j] = true; q[t++] = j; }
            }
    }
    return t;
}

MW_TEST(test_flood_matches_reference_bfs) {
    uint32_t s = 1;
    int bad = 0;
    for (int trial = 0; trial < 20000; trial++) {
        mw_game_t g;
        mw_game_init(&g, 10, 12);
        // sparse boards (0-4 mines: one huge area) and the real density (18)
        const int nm = (trial % 6 == 5) ? 18 : trial % 5;
        for (int k = 0; k < nm; k++) g.mine[lcg(&s) % (uint32_t)g.cells] = true;
        calc_adj(&g);
        g.placed = true;
        int start = -1;
        for (int k = 0; k < g.cells && start < 0; k++) {
            const int j = (int)(lcg(&s) % (uint32_t)g.cells);
            if (!g.mine[j]) start = j;
        }
        if (start < 0) continue;
        const int want = ref_flood(&g, start);
        mw_game_reveal(&g, start);
        int got = 0;
        for (int i = 0; i < g.cells; i++) got += g.open[i];
        if (got != want) bad++;
    }
    CHECK_EQ_INT(bad, 0);
}

// ---- A5: input sequences as the view feeds them --------------------------
// tap = press + release on the same cell
static mw_game_input_t tap(mw_game_t* g, int i, uint32_t t) {
    mw_game_on_press(g);
    return mw_game_on_release(g, i, t);
}

MW_TEST(test_input_sequences) {
    mw_game_t g;

    // hold on the X, slide off (no release event), then 3 taps unlock
    lose(&g);
    int ex = g.exploded;
    mw_game_on_press(&g);
    CHECK_EQ_INT(mw_game_on_long_press(&g, ex), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 1000), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 1200), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 1400), MW_GAME_IN_UNLOCK);

    // a hold on the X never unlocks, however often it is repeated
    lose(&g);
    ex = g.exploded;
    for (uint32_t k = 0; k < 10; k++) {
        mw_game_on_press(&g);
        CHECK_EQ_INT(mw_game_on_long_press(&g, ex), MW_GAME_IN_NONE);
        CHECK_EQ_INT(mw_game_on_release(&g, ex, 100 * k), MW_GAME_IN_NONE);
    }
    CHECK_EQ_INT(g.taps, 0);
    // two taps, a hold, two taps: the hold restarted the count
    CHECK_EQ_INT(tap(&g, ex, 2000), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 2100), MW_GAME_IN_NONE);
    mw_game_on_press(&g);
    mw_game_on_long_press(&g, ex);
    mw_game_on_release(&g, ex, 2600);
    CHECK_EQ_INT(tap(&g, ex, 2700), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 2800), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 2900), MW_GAME_IN_UNLOCK);

    // a tap elsewhere resets the count
    lose(&g);
    ex = g.exploded;
    CHECK_EQ_INT(tap(&g, ex, 0), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 100), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, (ex + 1) % g.cells, 200), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 300), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 400), MW_GAME_IN_NONE);
    CHECK_EQ_INT(tap(&g, ex, 500), MW_GAME_IN_UNLOCK);

    // long press flags without revealing; its release is swallowed once
    seed(77);
    mw_game_init(&g, 8, 8);
    mw_game_on_press(&g);
    CHECK_EQ_INT(mw_game_on_long_press(&g, 10), MW_GAME_IN_PAINT);
    CHECK(g.flag[10] && !g.open[10] && !g.placed);
    CHECK_EQ_INT(mw_game_on_release(&g, 10, 0), MW_GAME_IN_NONE);
    CHECK(g.flag[10] && !g.placed);
    // the next tap on the flagged cell is a real tap (blocked by the flag)
    CHECK_EQ_INT(tap(&g, 10, 10), MW_GAME_IN_PAINT);
    CHECK(!g.open[10] && !g.placed);
    // long press again removes the flag; a tap then reveals
    mw_game_on_press(&g);
    mw_game_on_long_press(&g, 10);
    mw_game_on_release(&g, 10, 20);
    CHECK(!g.flag[10]);
    CHECK_EQ_INT(tap(&g, 10, 30), MW_GAME_IN_PAINT);
    CHECK(g.open[10] && g.placed);

    // long press, slide off, then a tap on that cell is not swallowed
    seed(78);
    mw_game_init(&g, 8, 8);
    mw_game_on_press(&g);
    mw_game_on_long_press(&g, 5);
    CHECK(g.flag[5]);
    mw_game_on_press(&g);
    mw_game_on_long_press(&g, 5);               // unflag, slides off
    CHECK(!g.flag[5]);
    CHECK_EQ_INT(tap(&g, 5, 0), MW_GAME_IN_PAINT);
    CHECK(g.open[5]);

    // a long press on an open cell does nothing but swallow its release
    CHECK_EQ_INT(mw_game_on_long_press(&g, 5), MW_GAME_IN_NONE);
    CHECK(!g.flag[5]);

    // flag mode: taps flag
    seed(79);
    mw_game_init(&g, 8, 8);
    g.flag_mode = true;
    CHECK_EQ_INT(tap(&g, 3, 0), MW_GAME_IN_PAINT);
    CHECK(g.flag[3] && !g.placed);

    // out of range ids are ignored
    CHECK_EQ_INT(mw_game_on_release(&g, -1, 0), MW_GAME_IN_NONE);
    CHECK_EQ_INT(mw_game_on_release(&g, g.cells, 0), MW_GAME_IN_NONE);
    CHECK_EQ_INT(mw_game_on_long_press(&g, g.cells), MW_GAME_IN_NONE);

    // a won game ignores taps
    seed(7);
    mw_game_init(&g, 6, 4);
    mw_game_reveal(&g, 0);
    for (int i = 0; i < g.cells; i++) if (!g.mine[i]) mw_game_reveal(&g, i);
    CHECK(g.state == MW_GAME_WON);
    for (uint32_t k = 0; k < 5; k++) CHECK_EQ_INT(tap(&g, 0, k), MW_GAME_IN_NONE);
}

MW_TEST(test_keypad_move) {
    mw_game_t g;
    mw_game_init(&g, 10, 6);
    CHECK_EQ_INT(mw_game_move(&g, 0, 0, 1), 10);
    CHECK_EQ_INT(mw_game_move(&g, 15, 0, -1), 5);
    CHECK_EQ_INT(mw_game_move(&g, 5, 0, -1), 5);      // top edge
    CHECK_EQ_INT(mw_game_move(&g, 55, 0, 1), 55);     // bottom edge
    CHECK_EQ_INT(mw_game_move(&g, 10, -1, 0), 10);    // left edge stays in the row
    CHECK_EQ_INT(mw_game_move(&g, 19, 1, 0), 19);     // right edge
    CHECK_EQ_INT(mw_game_move(&g, 12, 1, 0), 13);
    CHECK_EQ_INT(mw_game_move(&g, -3, 1, 0), 0);      // no selection yet
}

MW_TEST(test_layout_fits) {
    // avail = board area for each panel. Portrait/square: page body minus
    // the header row; landscape: body minus the right-hand column.
    static const struct { int w, h; bool touch; int btn_h; const char* what; } cases[] = {
        { 232, 189, true,  40, "320x240 user theme, side column" },
        { 220, 182, true,  48, "320x240 project theme, side column" },
        { 312, 189, true,  40, "320x240 header row" },
        { 232, 269, true,  40, "240x320 user theme" },
        { 234, 292, true,  44, "240x320 project theme" },
        { 234, 200, false, 32, "240x240 buttons" },
        { 464, 416, true,  48, "480x480" },
        { 304, 416, true,  48, "320x480" },
        { 126,  41, false, 14, "128x64 mono" },
        { 120, 140, false, 20, "128x160 buttons" },
        {  10,   5, true,  40, "degenerate" },
        {   0,   0, true,  40, "empty" },
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        int c, r, s;
        const int cm = mw_game_cell_min(cases[k].touch, cases[k].btn_h);
        mw_game_layout(cases[k].w, cases[k].h, cm, &c, &r, &s);
        CHECK(c >= 1 && c <= MW_GAME_MAX_COLS && r >= 1 && r <= MW_GAME_MAX_ROWS && s >= 1);
        if (cases[k].w >= 1 && cases[k].h >= 1) {
            CHECK(c * s <= cases[k].w);
            CHECK(r * s <= cases[k].h);
        }
        // real panels get a playable board, finger-sized cells on touch
        if (cases[k].w >= 100 && cases[k].h >= 40) {
            CHECK(c * r >= 24);
            if (cases[k].touch) CHECK(s >= MW_GAME_CELL_MIN_TOUCH);
        }
        printf("    layout %3dx%-3d (%s) -> %2d x %2d cells of %2d px\n",
               cases[k].w, cases[k].h, cases[k].what, c, r, s);
    }
    CHECK_EQ_INT(mw_game_cell_min(true, 40), 36);
    CHECK_EQ_INT(mw_game_cell_min(true, 30), MW_GAME_CELL_MIN_TOUCH);
    CHECK_EQ_INT(mw_game_cell_min(false, 40), MW_GAME_CELL_MIN_KEYS);
}

int main(void) {
    RUN_TEST(test_empty_text_truncates_lvgl_map);
    RUN_TEST(test_map_has_every_cell_in_every_state);
    RUN_TEST(test_first_reveal_is_safe_and_mines_exact);
    RUN_TEST(test_adjacency_and_flood);
    RUN_TEST(test_flag_blocks_reveal_and_flood);
    RUN_TEST(test_win);
    RUN_TEST(test_unlock_gesture);
    RUN_TEST(test_flood_matches_reference_bfs);
    RUN_TEST(test_input_sequences);
    RUN_TEST(test_keypad_move);
    RUN_TEST(test_layout_fits);
    return mw_test_summary();
}

