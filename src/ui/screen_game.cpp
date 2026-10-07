// ---------------------------------------------------------------------------
//  Minesweeper (task 3 item 7).
//
//  The device starts - and returns after every lock - as a plain Minesweeper
//  game. The wallet program opens only after the user taps the EXPLODED mine
//  three times in a row within two seconds. Nothing on this screen mentions a
//  wallet.
//
//  The rules, the input state machine and the board geometry live in
//  game_model.c (host-tested by test/test_game.c); this file is the LVGL view.
//  The board is one lv_buttonmatrix (the 48 KiB LVGL heap would not hold 120
//  buttons with labels). Portrait: header row (title, counter, F, new game)
//  above the board. Landscape: the same controls in a column on the right so
//  the board gets the full height.
//
//  Controls: tap reveals, long press (or the F mode) flags. Button boards:
//  arrows move the selection, SELECT taps, holding SELECT flags, Back toggles
//  the F mode and a long Back starts a new game. The first reveal of a game
//  never hits a mine.
//
//  Exit invariant: mw_ui_modal_done(1) is the last access to s_g in any
//  callback path. The crypto task wakes up right after it and wipes s_g
//  through mw_ui_sync_call(), i.e. on the UI task after the callback returned.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "ui.h"
#include "game_model.h"
#include "../hal/log.h"

#include <stdio.h>
#include <string.h>

#if LVGL_VERSION_MAJOR >= 9
  #define GM_CREATE(p)            lv_buttonmatrix_create(p)
  #define GM_SET_MAP(o, m)        lv_buttonmatrix_set_map((o), (m))
  #define GM_SET_CTRL(o, i, c)    lv_buttonmatrix_set_button_ctrl((o), (i), (c))
  #define GM_CLR_CTRL_ALL(o, c)   lv_buttonmatrix_clear_button_ctrl_all((o), (c))
  #define GM_SELECTED(o)          lv_buttonmatrix_get_selected_button(o)
  #define GM_SET_SELECTED(o, i)   lv_buttonmatrix_set_selected_button((o), (i))
  #define GM_CHECKED              LV_BUTTONMATRIX_CTRL_CHECKED
  #define GM_CLICK_TRIG           LV_BUTTONMATRIX_CTRL_CLICK_TRIG
  #define GM_NO_REPEAT            LV_BUTTONMATRIX_CTRL_NO_REPEAT
  #define GM_NONE                 LV_BUTTONMATRIX_BUTTON_NONE
  typedef const char* const gm_map_t;
  typedef lv_buttonmatrix_ctrl_t gm_ctrl_t;
#else
  #define GM_CREATE(p)            lv_btnmatrix_create(p)
  #define GM_SET_MAP(o, m)        lv_btnmatrix_set_map((o), (m))
  #define GM_SET_CTRL(o, i, c)    lv_btnmatrix_set_btn_ctrl((o), (i), (c))
  #define GM_CLR_CTRL_ALL(o, c)   lv_btnmatrix_clear_btn_ctrl_all((o), (c))
  #define GM_SELECTED(o)          lv_btnmatrix_get_selected_btn(o)
  #define GM_SET_SELECTED(o, i)   lv_btnmatrix_set_selected_btn((o), (i))
  #define GM_CHECKED              LV_BTNMATRIX_CTRL_CHECKED
  #define GM_CLICK_TRIG           LV_BTNMATRIX_CTRL_CLICK_TRIG
  #define GM_NO_REPEAT            LV_BTNMATRIX_CTRL_NO_REPEAT
  #define GM_NONE                 LV_BTNMATRIX_BTN_NONE
  typedef const char* gm_map_t;
  typedef lv_btnmatrix_ctrl_t gm_ctrl_t;
#endif

// Fill of the other mines after a loss (the exploded one uses palette.danger).
#define GM_MINE_BG 0x5A1E1E

typedef struct {
    mw_page_t   page;
    lv_obj_t*   board;
    lv_obj_t*   lbl_mines;
    lv_obj_t*   btn_flag;
    mw_game_t   m;
    char        text[MW_GAME_MAX_CELLS][4];
    const char* map[MW_GAME_MAP_LEN];
    int         sel;             // keypad selection
    bool        sel_long;        // SELECT hold already sent as a long press
    bool        done;
} game_t;

static game_t s_g;

// ---------------------------------------------------------------- view
static void paint(game_t* g) {
    const int n = mw_game_build_map(&g->m, g->text, g->map, MW_GAME_MAP_LEN);
    if (n != g->m.cells) MW_LOGE("game", "map has %d buttons, want %d", n, g->m.cells);
    GM_SET_MAP(g->board, (gm_map_t*)g->map);
    GM_CLR_CTRL_ALL(g->board, GM_CHECKED);
    for (int i = 0; i < g->m.cells; i++) {
        // CLICK_TRIG: act on release, so a long press can flag first.
        // NO_REPEAT: a held finger must never count as more taps.
        GM_SET_CTRL(g->board, (uint32_t)i,
                    (gm_ctrl_t)(GM_CLICK_TRIG | GM_NO_REPEAT |
                                (mw_game_cell_shown(&g->m, i) ? GM_CHECKED : 0)));
    }
    if (g->sel >= 0) GM_SET_SELECTED(g->board, (uint32_t)g->sel);
    lv_obj_invalidate(g->board);
    if (g->lbl_mines) {
        if (g->m.state == MW_GAME_WON)       lv_label_set_text(g->lbl_mines, TX(XSTR_GAME_WON));
        else if (g->m.state == MW_GAME_LOST) lv_label_set_text(g->lbl_mines, TX(XSTR_GAME_LOST));
        else lv_label_set_text_fmt(g->lbl_mines, TX(XSTR_GAME_MINES), g->m.mines - mw_game_flags(&g->m));
    }
    if (g->btn_flag) {
        if (g->m.flag_mode) lv_obj_add_state(g->btn_flag, LV_STATE_CHECKED);
        else                MW_OBJ_CLEAR_STATE(g->btn_flag, LV_STATE_CHECKED);
    }
}

static void new_game(game_t* g) {
    mw_game_init(&g->m, g->m.cols, g->m.rows);
    g->sel_long = false;
    paint(g);
}

// Leaves the game. Nothing may touch s_g after mw_ui_modal_done(1).
static void game_finish(void) {
    s_g.done = true;
    mw_ui_set_button_hook(NULL, NULL);
    mw_ui_page_destroy(&s_g.page);
    mw_ui_modal_done(1);
}

// Applies a model result. Returns true when the game has finished: the
// caller must return at once without touching s_g.
static bool apply(mw_game_input_t r) {
    if (r == MW_GAME_IN_UNLOCK) { game_finish(); return true; }
    if (r == MW_GAME_IN_PAINT) paint(&s_g);
    return false;
}

static void board_cb(lv_event_t* e) {
    const lv_event_code_t code = lv_event_get_code(e);
    lv_obj_t* obj = MW_EVT_OBJ(e);
    if (s_g.done || obj != s_g.board) return;
    if (code == LV_EVENT_PRESSED) { (void)apply(mw_game_on_press(&s_g.m)); return; }
    uint32_t id = GM_SELECTED(obj);
    if (code == LV_EVENT_VALUE_CHANGED) {
        const uint32_t* p = (const uint32_t*)lv_event_get_param(e);
        if (p) id = *p;
    }
    if (id == GM_NONE || (int)id >= s_g.m.cells) return;
    if (code == LV_EVENT_LONG_PRESSED)
        (void)apply(mw_game_on_long_press(&s_g.m, (int)id));
    else if (code == LV_EVENT_VALUE_CHANGED)
        (void)apply(mw_game_on_release(&s_g.m, (int)id, mw_millis()));
}

#if LVGL_VERSION_MAJOR >= 9
// After a loss: the exploded cell red with a white X, other mines dark red.
static void board_draw_cb(lv_event_t* e) {
    if (s_g.done || s_g.m.state != MW_GAME_LOST) return;
    // 1-bit panels: danger and surface2 are both white there, which would
    // hide the X; they keep the CHECKED styling (white glyph on black).
    if (mw_metrics()->mono) return;
    lv_draw_task_t* t = lv_event_get_draw_task(e);
    lv_draw_dsc_base_t* base = (lv_draw_dsc_base_t*)lv_draw_task_get_draw_dsc(t);
    if (!base || base->part != LV_PART_ITEMS) return;
    const int id = (int)base->id1;
    if (id < 0 || id >= s_g.m.cells || !s_g.m.mine[id]) return;
    lv_draw_fill_dsc_t* fill = lv_draw_task_get_fill_dsc(t);
    if (fill) {
        fill->color = (id == s_g.m.exploded) ? mw_palette()->danger : lv_color_hex(GM_MINE_BG);
        fill->opa = LV_OPA_COVER;
    }
    lv_draw_label_dsc_t* lbl = lv_draw_task_get_label_dsc(t);
    if (lbl) lbl->color = lv_color_white();
}
#endif

static void new_cb(lv_event_t* e)  {
    MW_UNUSED(e);
    if (s_g.done) return;
    new_game(&s_g);
}

static void flag_cb(lv_event_t* e) {
    MW_UNUSED(e);
    if (s_g.done) return;
    s_g.m.flag_mode = !s_g.m.flag_mode;
    paint(&s_g);
}

// Button-only boards: the keypad indev would turn UP/DOWN into PREV/NEXT
// and move focus off the board, so the game reads the buttons directly.
static bool game_btn_hook(mw_button_t b, uint32_t hold_ms, bool released, void* user) {
    MW_UNUSED(user);
    if (s_g.done || !s_g.board) return true;
    game_t* g = &s_g;
    const bool edge = !released && hold_ms == 0;
    switch (b) {
    case MW_BTN_UP: case MW_BTN_DOWN: case MW_BTN_LEFT: case MW_BTN_RIGHT:
        if (!edge) return true;
        g->sel = mw_game_move(&g->m, g->sel,
                              b == MW_BTN_LEFT ? -1 : (b == MW_BTN_RIGHT ? 1 : 0),
                              b == MW_BTN_UP ? -1 : (b == MW_BTN_DOWN ? 1 : 0));
        GM_SET_SELECTED(g->board, (uint32_t)g->sel);
        lv_obj_invalidate(g->board);
        return true;
    case MW_BTN_SELECT:
        if (edge) {
            g->sel_long = false;
            (void)apply(mw_game_on_press(&g->m));
        } else if (!released) {
            if (!g->sel_long && hold_ms >= MW_BACK_LONG_MS) {
                g->sel_long = true;
                (void)apply(mw_game_on_long_press(&g->m, g->sel));
            }
        } else {
            // After a long press the model swallows this release.
            (void)apply(mw_game_on_release(&g->m, g->sel, mw_millis()));
        }
        return true;
    case MW_BTN_BACK:
        if (!released) return true;
        if (hold_ms >= MW_BACK_LONG_MS) new_game(g);
        else { g->m.flag_mode = !g->m.flag_mode; paint(g); }
        return true;
    default:
        return true;
    }
}

static lv_obj_t* small_button(lv_obj_t* parent, const char* text, lv_event_cb_t cb) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* b = MW_BTN_CREATE(parent);
    mw_theme_button(b);
    // TZ 4.1: at least 40 px under a finger, whatever the theme's btn_h.
    const lv_coord_t side = m->touch && m->btn_h < 40 ? 40 : m->btn_h;
    lv_obj_set_size(b, side, side);
    lv_obj_t* l = lv_label_create(b);
    lv_label_set_text(l, text);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, NULL);
    return b;
}

static lv_obj_t* plain_box(lv_obj_t* parent) {
    lv_obj_t* o = lv_obj_create(parent);
    lv_obj_remove_style_all(o);
    MW_OBJ_CLEAR_FLAG(o, LV_OBJ_FLAG_SCROLLABLE);
    return o;
}

// Controls: title, mines counter, F (flag mode), new game. side: a column
// right of the board; otherwise a header row above it.
static lv_obj_t* build_controls(game_t* g, lv_obj_t* body, bool side, lv_obj_t** bnew) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* ctl = plain_box(body);
    lv_obj_t* title;
    lv_obj_t* btns;
    if (side) {
        lv_obj_set_flex_flow(body, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(body, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_size(ctl, LV_SIZE_CONTENT, lv_pct(100));
        lv_obj_set_flex_flow(ctl, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(ctl, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_row(ctl, m->gap, LV_PART_MAIN);
        title = lv_label_create(ctl);
        g->lbl_mines = lv_label_create(ctl);
        btns = plain_box(ctl);
        lv_obj_set_size(btns, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
        lv_obj_set_flex_flow(btns, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_column(btns, m->gap, LV_PART_MAIN);
    } else {
        lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_size(ctl, lv_pct(100), LV_SIZE_CONTENT);
        lv_obj_set_flex_flow(ctl, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(ctl, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_column(ctl, m->gap, LV_PART_MAIN);
        // Title over the counter on the left, buttons on the right.
        lv_obj_t* txt = plain_box(ctl);
        lv_obj_set_height(txt, LV_SIZE_CONTENT);
        lv_obj_set_flex_grow(txt, 1);
        lv_obj_set_flex_flow(txt, LV_FLEX_FLOW_COLUMN);
        title = lv_label_create(txt);
        lv_obj_set_width(title, lv_pct(100));
        lv_label_set_long_mode(title, LV_LABEL_LONG_DOT);
        g->lbl_mines = lv_label_create(txt);
        btns = ctl;
    }
    lv_obj_add_style(title, mw_style_title(), LV_PART_MAIN);
    lv_obj_set_style_text_font(title, m->font_body, LV_PART_MAIN);
    lv_label_set_text(title, TX(XSTR_GAME_TITLE));
    lv_obj_add_style(g->lbl_mines, mw_style_dim(), LV_PART_MAIN);
    lv_label_set_text_fmt(g->lbl_mines, TX(XSTR_GAME_MINES), 99);   // widest, for layout
    g->btn_flag = small_button(btns, "F", flag_cb);
    lv_obj_add_flag(g->btn_flag, LV_OBJ_FLAG_CHECKABLE);
    *bnew = small_button(btns, LV_SYMBOL_REFRESH, new_cb);
    return ctl;
}

static void measure_board(game_t* g, lv_obj_t* body, lv_obj_t* ctl, bool side, int cell_min,
                          int* cols, int* rows, int* cell) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_update_layout(g->page.scr);
    int avail_w = (int)lv_obj_get_content_width(body);
    int avail_h = (int)lv_obj_get_content_height(body);
    if (side) avail_w -= (int)lv_obj_get_width(ctl) + (int)m->gap;
    else      avail_h -= (int)lv_obj_get_height(ctl) + (int)m->gap;
    mw_game_layout(avail_w, avail_h, cell_min, cols, rows, cell);
}

static void game_build(void* arg) {
    game_t* g = (game_t*)arg;
    const mw_metrics_t* m = mw_metrics();
    bool side = m->w > m->h && !m->compact;   // controls in a right column
    g->done = false;
    g->sel = 0;

    mw_ui_page_create(&g->page, NULL, false);
    lv_obj_t* body = g->page.body;

    lv_obj_t* bnew = NULL;
    lv_obj_t* ctl = build_controls(g, body, side, &bnew);

    // Board geometry from the space actually left (measured, not guessed).
    const int cell_min = mw_game_cell_min(m->touch, m->btn_h);
    int cols, rows, cell;
    measure_board(g, body, ctl, side, cell_min, &cols, &rows, &cell);
    if (side && cell < cell_min) {
        // The column is too wide for this theme: header row instead.
        MW_OBJ_DEL(ctl);
        side = false;
        ctl = build_controls(g, body, side, &bnew);
        measure_board(g, body, ctl, side, cell_min, &cols, &rows, &cell);
    }
    mw_game_init(&g->m, cols, rows);

    g->board = GM_CREATE(body);
    if (side) lv_obj_move_to_index(g->board, 0);   // board left, controls right
    lv_obj_set_size(g->board, cell * cols, cell * rows);
    lv_obj_set_style_pad_all(g->board, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(g->board, cell < 16 ? 1 : 2, LV_PART_MAIN);
    // Digits must fit the cell: drop to the small font on tight boards.
    if (lv_font_get_line_height(m->font_body) > cell - 6)
        lv_obj_set_style_text_font(g->board, m->font_small, LV_PART_ITEMS);
    lv_obj_set_style_bg_color(g->board, mw_palette()->bg, LV_PART_MAIN);
    // A thin frame, so a board with opened (background-coloured) cells
    // still shows its edges.
    lv_obj_set_style_border_width(g->board, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(g->board, mw_palette()->border, LV_PART_MAIN);
    lv_obj_set_style_radius(g->board, 2, LV_PART_ITEMS);
    lv_obj_set_style_bg_color(g->board, mw_palette()->surface2, LV_PART_ITEMS);
    lv_obj_set_style_bg_color(g->board, mw_palette()->bg,
                              (lv_style_selector_t)LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_set_style_text_color(g->board, mw_palette()->text, LV_PART_ITEMS);
    lv_obj_set_style_text_color(g->board, mw_palette()->accent,
                                (lv_style_selector_t)LV_PART_ITEMS | LV_STATE_CHECKED);
    lv_obj_add_event_cb(g->board, board_cb, LV_EVENT_PRESSED, NULL);
    lv_obj_add_event_cb(g->board, board_cb, LV_EVENT_VALUE_CHANGED, NULL);
    lv_obj_add_event_cb(g->board, board_cb, LV_EVENT_LONG_PRESSED, NULL);
#if LVGL_VERSION_MAJOR >= 9
    lv_obj_add_flag(g->board, LV_OBJ_FLAG_SEND_DRAW_TASK_EVENTS);
    lv_obj_add_event_cb(g->board, board_draw_cb, LV_EVENT_DRAW_TASK_ADDED, NULL);
#endif
    MW_OBJ_CLEAR_FLAG(g->board, LV_OBJ_FLAG_SCROLLABLE);

    mw_ui_focus_add(&g->page, g->board);
    mw_ui_focus_add(&g->page, g->btn_flag);
    mw_ui_focus_add(&g->page, bnew);
    lv_group_focus_obj(g->board);

    if (m->buttons) {
        // The selected cell gets an outline; the buttons drive the board.
        const lv_style_selector_t sel_focus =
            (lv_style_selector_t)LV_PART_ITEMS | LV_STATE_FOCUSED;
        lv_obj_set_style_border_width(g->board, 2, sel_focus);
        lv_obj_set_style_border_color(g->board, mw_palette()->focus_outline, sel_focus);
        mw_ui_set_button_hook(game_btn_hook, NULL);
    } else {
        g->sel = -1;
    }

    new_game(g);
    MW_LOGD("game", "board %dx%d, cell %d px, %d mines", cols, rows, cell, g->m.mines);
}

// Runs on the UI task, so it cannot overlap a board callback.
static void wipe_job(void* arg) {
    MW_UNUSED(arg);
    memset(&s_g, 0, sizeof(s_g));
}

void mw_screen_game_run(void) {
    MW_LOGI("game", "start screen");
    // A stale lock request would make every modal_call return -1 at once.
    mw_ui_autolock_arm(false);
    uint32_t backoff = 50, last_log = 0;
    bool logged = false;
    // Only the gesture (result 1) leaves the game; any other close of the
    // page rebuilds it instead of falling through to the password prompt.
    for (;;) {
        mw_ui_sync_call(wipe_job, NULL);
        const int32_t r = mw_ui_modal_call(game_build, &s_g);
        if (r == 1) break;
        const uint32_t now = mw_millis();
        if (!logged || now - last_log >= 1000) {
            MW_LOGI("game", "page closed (%ld): back to the game", (long)r);
            last_log = now;
            logged = true;
        }
        mw_delay_ms(backoff);
        backoff = backoff * 2 > 1000 ? 1000 : backoff * 2;
    }
    mw_ui_sync_call(wipe_job, NULL);
}
