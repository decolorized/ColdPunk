// Button navigation of the on-screen keyboards - see keyboard_nav.h.
//
// SPDX-License-Identifier: MIT
#include "keyboard_nav.h"

#include <string.h>

static bool is_arrow(mw_button_t b) {
    return b == MW_BTN_UP || b == MW_BTN_DOWN || b == MW_BTN_LEFT || b == MW_BTN_RIGHT;
}

static uint32_t bit(mw_button_t b) { return 1u << (unsigned)b; }

void mw_kn_reset(mw_kn_t* k) {
    if (k) memset(k, 0, sizeof(*k));
}

mw_kn_out_t mw_kn_event(mw_kn_t* k, mw_button_t b, uint32_t hold_ms, bool released,
                        uint32_t now_ms) {
    mw_kn_out_t o;
    o.act = MW_KN_NONE;
    o.dir = MW_BTN_NONE;
    o.undo_move = false;
    if (!k || (unsigned)b == 0 || (unsigned)b >= 8) return o;
    const unsigned i = (unsigned)b;

    // ---- release ------------------------------------------------------------
    if (released) {
        const bool was_held = (k->held & bit(b)) != 0;
        k->held &= ~bit(b);
        if (k->consumed & bit(b)) {
            k->consumed &= ~bit(b);
            return o;
        }
        if (!was_held || k->long_fired[i]) return o;
        if (b == MW_BTN_SELECT) o.act = MW_KN_ACTIVATE;
        else if (b == MW_BTN_BACK) o.act = MW_KN_BACKSPACE;
        return o;
    }

    // ---- press edge ---------------------------------------------------------
    if (hold_ms == 0) {
        k->held |= bit(b);
        k->consumed &= ~bit(b);
        k->press_ms[i]   = now_ms;
        k->long_fired[i] = false;
        k->moves[i]      = 0;
        if (!is_arrow(b)) return o;

        // Another arrow already down: a chord.
        for (unsigned j = 1; j < 8; ++j) {
            const mw_button_t other = (mw_button_t)j;
            if (j == i || !is_arrow(other) || !(k->held & bit(other))) continue;
            if (k->consumed & bit(other)) continue;        // part of a chord already
            o.act = MW_KN_LAYOUT;
            // Take back the single step the first arrow made, if the chord
            // came quickly enough to be one gesture.
            o.undo_move = k->moves[j] == 1 &&
                          (uint32_t)(now_ms - k->press_ms[j]) <= MW_KN_CHORD_MS;
            k->consumed |= bit(b) | bit(other);
            return o;
        }
        k->repeat_ms[i] = now_ms + MW_KN_REPEAT_DELAY_MS;
        k->moves[i] = 1;
        o.act = MW_KN_MOVE;
        o.dir = b;
        return o;
    }

    // ---- held -----------------------------------------------------------------
    if (!(k->held & bit(b)) || (k->consumed & bit(b))) return o;
    if (is_arrow(b)) {
        if ((int32_t)(now_ms - k->repeat_ms[i]) >= 0) {
            k->repeat_ms[i] = now_ms + MW_KN_REPEAT_MS;
            k->moves[i]++;
            o.act = MW_KN_MOVE;
            o.dir = b;
        }
        return o;
    }
    if ((b == MW_BTN_SELECT || b == MW_BTN_BACK) && !k->long_fired[i] &&
        hold_ms >= MW_KN_LONG_MS) {
        k->long_fired[i] = true;
        o.act = (b == MW_BTN_SELECT) ? MW_KN_FINISH : MW_KN_CANCEL;
    }
    return o;
}

// ---------------------------------------------------------------------------
static bool alive(mw_kn_live_fn live, void* ctx, int i) {
    return live ? live(i, ctx) : true;
}

int mw_kn_linear_step(int count, int cur, int dir, mw_kn_live_fn live, void* ctx) {
    if (count <= 0) return -1;
    if (cur < 0 || cur >= count) cur = (dir >= 0) ? count - 1 : 0;
    const int d = (dir >= 0) ? 1 : -1;
    int i = cur;
    for (int guard = 0; guard < count; ++guard) {
        i += d;
        if (i < 0) i = count - 1;
        if (i >= count) i = 0;
        if (i == cur) break;
        if (alive(live, ctx, i)) return i;
    }
    return cur;
}

// Nearest live cell of row `row`, starting from column `col`.
static int nearest_in_row(int n, int cols, int row, int col, mw_kn_live_fn live,
                          void* ctx) {
    const int first = row * cols;
    if (first >= n) return -1;
    int last = first + cols - 1;
    if (last >= n) last = n - 1;
    int c = first + col;
    if (c > last) c = last;
    for (int dist = 0; dist < cols; ++dist) {
        const int a = c - dist, b = c + dist;
        if (a >= first && alive(live, ctx, a)) return a;
        if (dist && b <= last && alive(live, ctx, b)) return b;
    }
    return -1;
}

int mw_kn_grid_step(int n, int cols, int cur, mw_button_t dir,
                    mw_kn_live_fn live, void* ctx) {
    if (n <= 0 || cols <= 0) return -1;
    if (cur < 0) cur = 0;
    if (cur >= n) cur = n - 1;
    const int rows = (n + cols - 1) / cols;
    const int row = cur / cols, col = cur % cols;

    switch (dir) {
    case MW_BTN_LEFT:
    case MW_BTN_RIGHT: {
        const int d = (dir == MW_BTN_RIGHT) ? 1 : -1;
        for (int i = cur + d; i >= 0 && i < n; i += d)
            if (alive(live, ctx, i)) return i;
        return cur;
    }
    case MW_BTN_UP:
        for (int r = row - 1; r >= 0; --r) {
            const int t = nearest_in_row(n, cols, r, col, live, ctx);
            if (t >= 0) return t;
        }
        return -1;
    case MW_BTN_DOWN:
        for (int r = row + 1; r < rows; ++r) {
            const int t = nearest_in_row(n, cols, r, col, live, ctx);
            if (t >= 0) return t;
        }
        return cur;
    default:
        return cur;
    }
}
