// Minesweeper model (see game_model.h).
#include "game_model.h"
#include "../crypto/random.h"

#include <stdio.h>
#include <string.h>

// LV_SYMBOL_CLOSE (U+F00D), present in every built-in Montserrat face.
#define GM_SYM_EXPLODED "\xEF\x80\x8D"
#define GM_BLANK        " "

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

int mw_game_cell_min(bool touch, int btn_h) {
    if (!touch) return MW_GAME_CELL_MIN_KEYS;
    return btn_h - 4 > MW_GAME_CELL_MIN_TOUCH ? btn_h - 4 : MW_GAME_CELL_MIN_TOUCH;
}

void mw_game_layout(int avail_w, int avail_h, int cell_min,
                    int* cols, int* rows, int* cell) {
    if (avail_w < 1) avail_w = 1;
    if (avail_h < 1) avail_h = 1;
    if (cell_min < 1) cell_min = 1;
    // As many cells of cell_min as fit, within the board limits; then the
    // largest square cell for that grid; then use any room that is left.
    int c = clampi(avail_w / cell_min, MW_GAME_MIN_COLS, MW_GAME_MAX_COLS);
    int r = clampi(avail_h / cell_min, MW_GAME_MIN_ROWS, MW_GAME_MAX_ROWS);
    int s = avail_w / c < avail_h / r ? avail_w / c : avail_h / r;
    if (s < 1) s = 1;
    c = clampi(avail_w / s, 1, MW_GAME_MAX_COLS);
    r = clampi(avail_h / s, 1, MW_GAME_MAX_ROWS);
    *cols = c; *rows = r; *cell = s;
}

void mw_game_init(mw_game_t* g, int cols, int rows) {
    memset(g, 0, sizeof(*g));
    cols = clampi(cols, 2, MW_GAME_MAX_COLS);
    rows = clampi(rows, 2, MW_GAME_MAX_ROWS);
    g->cols = cols; g->rows = rows; g->cells = cols * rows;
    g->mines = g->cells * 15 / 100;
    if (g->mines < 4) g->mines = 4;
    if (g->mines > g->cells - 1) g->mines = g->cells - 1;
    g->state = MW_GAME_PLAY;
    g->exploded = -1;
    g->long_pressed = -1;
}

static uint32_t rnd32(void) { uint32_t v = 0; mw_random_bytes(&v, sizeof v); return v; }

static void place_mines(mw_game_t* g, int safe) {
    memset(g->mine, 0, sizeof g->mine);
    const bool keep_ring = (g->cells - g->mines > 9);
    int placed = 0;
    while (placed < g->mines) {
        const int i = (int)(rnd32() % (uint32_t)g->cells);
        if (i == safe || g->mine[i]) continue;
        const int dr = i / g->cols - safe / g->cols;
        const int dc = i % g->cols - safe % g->cols;
        if (keep_ring && dr >= -1 && dr <= 1 && dc >= -1 && dc <= 1) continue;
        g->mine[i] = true;
        placed++;
    }
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
    g->placed = true;
}

static void flood(mw_game_t* g, int start) {
    // Mark on push: every cell enters the stack at most once, so it never
    // holds more than g->cells entries. Static: the UI task stack is 8 KiB.
    static uint8_t stack[MW_GAME_MAX_CELLS];
    int sp = 0;
    if (g->open[start] || g->flag[start]) return;
    g->open[start] = true;
    stack[sp++] = (uint8_t)start;
    while (sp > 0) {
        const int i = stack[--sp];
        if (g->adj[i] != 0 || g->mine[i]) continue;
        const int r = i / g->cols, c = i % g->cols;
        for (int dr = -1; dr <= 1; dr++)
            for (int dc = -1; dc <= 1; dc++) {
                const int rr = r + dr, cc = c + dc;
                if (rr < 0 || rr >= g->rows || cc < 0 || cc >= g->cols) continue;
                const int j = rr * g->cols + cc;
                if (g->open[j] || g->flag[j]) continue;
                g->open[j] = true;
                stack[sp++] = (uint8_t)j;
            }
    }
}

void mw_game_reveal(mw_game_t* g, int i) {
    if (g->state != MW_GAME_PLAY || i < 0 || i >= g->cells) return;
    if (g->flag[i] || g->open[i]) return;
    if (!g->placed) place_mines(g, i);
    if (g->mine[i]) {
        g->state = MW_GAME_LOST;
        g->exploded = i;
        g->taps = 0;
        return;
    }
    flood(g, i);
    for (int k = 0; k < g->cells; k++)
        if (!g->mine[k] && !g->open[k]) return;
    g->state = MW_GAME_WON;
}

void mw_game_toggle_flag(mw_game_t* g, int i) {
    if (g->state != MW_GAME_PLAY || i < 0 || i >= g->cells || g->open[i]) return;
    g->flag[i] = !g->flag[i];
}

int mw_game_flags(const mw_game_t* g) {
    int n = 0;
    for (int i = 0; i < g->cells; i++) n += g->flag[i];
    return n;
}

bool mw_game_unlock_tap(mw_game_t* g, int i, uint32_t now) {
    if (g->state != MW_GAME_LOST) return false;
    if (i != g->exploded) { g->taps = 0; return false; }
    if (g->taps == 0 || now - g->first_tap_ms > MW_GAME_UNLOCK_WINDOW_MS) {
        g->taps = 0;
        g->first_tap_ms = now;
    }
    return ++g->taps >= MW_GAME_UNLOCK_TAPS;
}

void mw_game_unlock_reset(mw_game_t* g) { g->taps = 0; }

mw_game_input_t mw_game_on_press(mw_game_t* g) {
    g->long_pressed = -1;
    return MW_GAME_IN_NONE;
}

mw_game_input_t mw_game_on_long_press(mw_game_t* g, int i) {
    if (i < 0 || i >= g->cells) return MW_GAME_IN_NONE;
    g->long_pressed = i;
    if (g->state == MW_GAME_PLAY && !g->open[i]) {
        mw_game_toggle_flag(g, i);
        return MW_GAME_IN_PAINT;
    }
    if (g->state == MW_GAME_LOST) mw_game_unlock_reset(g);
    return MW_GAME_IN_NONE;
}

mw_game_input_t mw_game_on_release(mw_game_t* g, int i, uint32_t now_ms) {
    if (i < 0 || i >= g->cells) return MW_GAME_IN_NONE;
    if (g->long_pressed == i) { g->long_pressed = -1; return MW_GAME_IN_NONE; }
    g->long_pressed = -1;
    switch (g->state) {
    case MW_GAME_LOST:
        return mw_game_unlock_tap(g, i, now_ms) ? MW_GAME_IN_UNLOCK : MW_GAME_IN_NONE;
    case MW_GAME_PLAY:
        if (g->flag_mode) mw_game_toggle_flag(g, i);
        else              mw_game_reveal(g, i);
        return MW_GAME_IN_PAINT;
    default:
        return MW_GAME_IN_NONE;
    }
}

int mw_game_move(const mw_game_t* g, int i, int dc, int dr) {
    if (g->cells <= 0) return 0;
    if (i < 0 || i >= g->cells) return 0;
    const int r = clampi(i / g->cols + dr, 0, g->rows - 1);
    const int c = clampi(i % g->cols + dc, 0, g->cols - 1);
    return r * g->cols + c;
}

bool mw_game_cell_shown(const mw_game_t* g, int i) {
    return g->open[i] || (g->state == MW_GAME_LOST && g->mine[i]);
}

const char* mw_game_cell_text(const mw_game_t* g, int i, char out[4]) {
    if (g->state == MW_GAME_LOST && g->mine[i])
        snprintf(out, 4, "%s", i == g->exploded ? GM_SYM_EXPLODED : "*");
    else if (g->open[i] && g->adj[i])
        snprintf(out, 4, "%d", (int)g->adj[i]);
    else if (!g->open[i] && g->flag[i])
        snprintf(out, 4, "%s", "F");
    else
        snprintf(out, 4, "%s", GM_BLANK);
    return out;
}

int mw_game_build_map(const mw_game_t* g, char text[][4], const char* map[], size_t map_len) {
    if (map_len < (size_t)(g->cells + g->rows)) return -1;
    size_t k = 0;
    for (int r = 0; r < g->rows; r++) {
        for (int c = 0; c < g->cols; c++) {
            const int i = r * g->cols + c;
            mw_game_cell_text(g, i, text[i]);
            map[k++] = text[i];
        }
        if (r + 1 < g->rows) map[k++] = "\n";
    }
    map[k] = "";
    // Count exactly like lv_buttonmatrix.c allocate_button_areas_and_controls().
    int n = 0;
    for (size_t j = 0; map[j] && map[j][0] != '\0'; j++)
        if (strcmp(map[j], "\n") != 0) n++;
    return n;
}
