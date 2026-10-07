// ---------------------------------------------------------------------------
//  Numeric keypad and the typed-number confirmation gate (task2 item 6).
//
//      ┌──────────────────────────────┐
//      │ Подтверждение                │
//      │ Введите число 4821           │
//      │            48_               │
//      │   [1]  [2]  [3]              │
//      │   [4]  [5]  [6]              │
//      │   [7]  [8]  [9]              │
//      │   [⌫]  [0]  [OK]             │
//      │          [Отмена]            │
//      └──────────────────────────────┘
//
//  In landscape the hint, the value and [Отмена] move to a left column and
//  the same 3x4 pad sits on the right (see pin_build).
//
//  A destructive action (delete a wallet, factory reset, format the card,
//  burn the eFuse key) is no longer a "Yes" tap away: the device shows a
//  random four-digit number and the user has to type it back. Two taps in a
//  row cannot do it, a pocket cannot do it, and a user who is not reading
//  the screen cannot do it either.
//
//  mw_screen_pin_run() runs on the caller's task and marshals onto the LVGL
//  task like every other blocking helper; mw_ui_confirm_code() is a plain
//  sequence of blocking helpers.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../crypto/random.h"
#include "../crypto/memzero.h"

#include <stdio.h>
#include <string.h>

#define PIN_MAX 16

typedef struct {
    mw_page_t   page;
    const char* title;
    const char* hint;
    char        buf[PIN_MAX + 1];
    size_t      len;
    size_t      cap;          // digits allowed (caller's out_cap - 1)
    bool        mask;
    lv_obj_t*   lbl_value;
    bool        done;
} pin_ctx_t;

static pin_ctx_t s_pin;

static void pin_paint(pin_ctx_t* c) {
    if (!c->lbl_value) return;
    char shown[PIN_MAX + 2];
    if (c->mask) {
        size_t i;
        for (i = 0; i < c->len && i < PIN_MAX; i++) shown[i] = '*';
        shown[i] = '\0';
    } else {
        snprintf(shown, sizeof(shown), "%s", c->buf);
    }
    lv_label_set_text_fmt(c->lbl_value, "%s_", shown);
}

static void pin_finish(pin_ctx_t* c, int32_t r) {
    if (c->done) return;
    c->done = true;
    mw_ui_page_destroy(&c->page);
    mw_ui_modal_done(r);
}

static void pin_digit_cb(lv_event_t* e) {
    const int d = (int)(intptr_t)lv_event_get_user_data(e);
    pin_ctx_t* c = &s_pin;
    if (c->len >= c->cap || c->len >= PIN_MAX) return;
    c->buf[c->len++] = (char)('0' + d);
    c->buf[c->len]   = '\0';
    pin_paint(c);
}

static void pin_bksp_cb(lv_event_t* e) {
    MW_UNUSED(e);
    pin_ctx_t* c = &s_pin;
    if (c->len > 0) c->buf[--c->len] = '\0';
    pin_paint(c);
}

static void pin_ok_cb(lv_event_t* e)     { MW_UNUSED(e); pin_finish(&s_pin, 1); }
static void pin_cancel_cb(lv_event_t* e) { MW_UNUSED(e); pin_finish(&s_pin, 0); }
static void pin_escape(void* user)       { MW_UNUSED(user); pin_finish(&s_pin, 0); }

static void pin_build(void* arg) {
    pin_ctx_t* c = (pin_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();
    c->done = false;

    // Three layouts, all sized from the room measured after everything else
    // is laid out:
    //   portrait   hint, value, 3x4 phone pad, [Cancel] footer;
    //   landscape  hint, value and [Cancel] in a left column, the 3x4 pad
    //              on the right;
    //   tiny       (128x64 with buttons) the hint is the title, the value
    //              sits left of a 6x2 pad, Back cancels.
    const bool tiny = m->compact && m->buttons;
    const bool side = tiny || m->landscape;
    const int  cols = tiny ? 6 : 3;
    const int  rows = tiny ? 2 : 4;

    mw_ui_page_create(&c->page, (tiny && c->hint && c->hint[0]) ? c->hint : c->title, false);
    mw_ui_page_set_escape(&c->page, pin_escape, c);
    // The hint carries the code: small font so it fits one line.
    if (tiny && c->page.title) {
        lv_obj_set_style_text_font(c->page.title, m->font_small, LV_PART_MAIN);
        lv_obj_set_height(c->page.title, LV_SIZE_CONTENT);
    }

    lv_obj_t* info = c->page.body;
    if (side) {
        lv_obj_set_flex_flow(c->page.body, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_column(c->page.body, m->gap, LV_PART_MAIN);
        info = lv_obj_create(c->page.body);
        lv_obj_remove_style_all(info);
        lv_obj_set_size(info, lv_pct(tiny ? 30 : 40), lv_pct(100));
        lv_obj_set_flex_flow(info, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_flex_align(info, tiny ? LV_FLEX_ALIGN_CENTER : LV_FLEX_ALIGN_START,
                              LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
        lv_obj_set_style_pad_row(info, m->gap, LV_PART_MAIN);
        MW_OBJ_CLEAR_FLAG(info, LV_OBJ_FLAG_SCROLLABLE);
    }

    if (!tiny && c->hint && c->hint[0]) mw_ui_label(info, c->hint, NULL);

    c->lbl_value = mw_ui_label(info, "_", mw_style_mono());
    lv_obj_set_style_text_align(c->lbl_value, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_set_style_text_font(c->lbl_value, m->font_title, LV_PART_MAIN);

    lv_obj_t* grid = lv_obj_create(c->page.body);
    lv_obj_remove_style_all(grid);
    if (side) lv_obj_set_size(grid, 0, lv_pct(100));
    else      lv_obj_set_size(grid, lv_pct(100), 0);
    lv_obj_set_flex_grow(grid, 1);
    lv_obj_set_flex_flow(grid, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_row(grid, m->gap, LV_PART_MAIN);
    lv_obj_set_style_pad_column(grid, m->gap, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(grid, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* bc = NULL;
    if (tiny) {
        // No Cancel button: the Back key cancels (pin_escape).
    } else if (side) {
        lv_obj_t* sp = lv_obj_create(info);
        lv_obj_remove_style_all(sp);
        lv_obj_set_width(sp, lv_pct(100));
        lv_obj_set_flex_grow(sp, 1);
        bc = mw_ui_button(info, T(STR_CANCEL), pin_cancel_cb, NULL);
        lv_obj_set_flex_grow(bc, 0);
        lv_obj_set_width(bc, lv_pct(100));
    } else {
        lv_obj_t* f = mw_ui_page_footer(&c->page);
        bc = mw_ui_button(f, T(STR_CANCEL), pin_cancel_cb, NULL);
        lv_obj_set_flex_grow(bc, 1);
    }

    lv_obj_update_layout(c->page.scr);
    const lv_coord_t gw = (lv_coord_t)lv_obj_get_content_width(grid);
    const lv_coord_t gh = (lv_coord_t)lv_obj_get_content_height(grid);
    lv_coord_t bw = (lv_coord_t)((gw - (cols - 1) * m->gap) / cols);
    lv_coord_t bh = (lv_coord_t)((gh - (rows - 1) * m->gap) / rows);
    if (bh > m->btn_h * 3 / 2) bh = (lv_coord_t)(m->btn_h * 3 / 2);
    if (bw < 8) bw = 8;
    if (bh < 8) bh = 8;
    // Exactly `cols` cells per row; the spare room is split on both sides.
    const lv_coord_t spare_w = (lv_coord_t)(gw - cols * bw - (cols - 1) * m->gap);
    const lv_coord_t spare_h = (lv_coord_t)(gh - rows * bh - (rows - 1) * m->gap);
    lv_obj_set_style_pad_left(grid, (lv_coord_t)(spare_w / 2), LV_PART_MAIN);
    lv_obj_set_style_pad_right(grid, (lv_coord_t)(spare_w - spare_w / 2), LV_PART_MAIN);
    lv_obj_set_style_pad_top(grid, (lv_coord_t)(spare_h / 2), LV_PART_MAIN);

    // caps[] index: 0..8 = digits 1..9, 9 = backspace, 10 = 0, 11 = OK.
    static const char* const caps[12] = {
        "1", "2", "3", "4", "5", "6", "7", "8", "9", LV_SYMBOL_BACKSPACE, "0", LV_SYMBOL_OK
    };
    static const uint8_t order_pad[12]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    static const uint8_t order_tiny[12] = { 0, 1, 2, 3, 4, 9, 5, 6, 7, 8, 10, 11 };
    const uint8_t* order = tiny ? order_tiny : order_pad;
    lv_obj_t* first = NULL;
    for (int k = 0; k < 12; k++) {
        const int i = order[k];
        lv_obj_t* b;
        if (i == 9)       b = mw_ui_button(grid, caps[i], pin_bksp_cb, NULL);
        else if (i == 11) b = mw_ui_button(grid, caps[i], pin_ok_cb, NULL);
        else {
            const int digit = (i == 10) ? 0 : i + 1;
            b = mw_ui_button(grid, caps[i], pin_digit_cb, (void*)(intptr_t)digit);
        }
        lv_obj_set_flex_grow(b, 0);
        lv_obj_set_style_pad_all(b, 0, LV_PART_MAIN);
        lv_obj_set_style_min_width(b, 0, LV_PART_MAIN);
        lv_obj_set_style_min_height(b, 0, LV_PART_MAIN);
        lv_obj_set_size(b, bw, bh);
        if (tiny) {
            lv_obj_t* l = lv_obj_get_child(b, 0);
            if (l) {
                lv_obj_set_style_text_font(l, m->font_small, LV_PART_MAIN);
                lv_label_set_long_mode(l, LV_LABEL_LONG_CLIP);
                lv_obj_set_size(l, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
                lv_obj_center(l);
            }
        }
        if (i == 11 && !m->mono) lv_obj_set_style_bg_color(b, mw_palette()->accent, LV_PART_MAIN);
        mw_ui_focus_add(&c->page, b);
        if (!first) first = b;
    }
    if (bc) mw_ui_focus_add(&c->page, bc);

    if (first) lv_group_focus_obj(first);
    pin_paint(c);
}

mw_err_t mw_screen_pin_run(const char* title, const char* hint, char* out,
                           size_t out_cap, bool mask) {
    if (!out || out_cap < 2) return MW_ERR_INVALID_ARG;
    out[0] = '\0';

    memset(&s_pin, 0, sizeof(s_pin));
    s_pin.title = title ? title : TX(XSTR_CODE_TITLE);
    s_pin.hint  = hint;
    s_pin.cap   = out_cap - 1;
    if (s_pin.cap > PIN_MAX) s_pin.cap = PIN_MAX;
    s_pin.mask  = mask;

    const int32_t r = mw_ui_modal_call(pin_build, &s_pin);
    if (r == 1) snprintf(out, out_cap, "%s", s_pin.buf);
    mw_memzero(s_pin.buf, sizeof(s_pin.buf));
    s_pin.len = 0;
    return (r == 1) ? MW_OK : MW_ERR_ABORTED;
}

// ---------------------------------------------------------------------------
bool mw_ui_confirm_code(const char* title, const char* body) {
    // Four digits, first one never zero, so the number reads as a number.
    uint8_t rnd[4];
    mw_random_bytes(rnd, sizeof(rnd));
    char code[5];
    code[0] = (char)('1' + (rnd[0] % 9));
    for (int i = 1; i < 4; i++) code[i] = (char)('0' + (rnd[i] % 10));
    code[4] = '\0';

    char text[256];
    snprintf(text, sizeof(text), "%s\n\n", body ? body : "");
    size_t used = strlen(text);
    snprintf(text + used, sizeof(text) - used, TX(XSTR_CODE_PROMPT), code);
    mw_ui_message(title ? title : TX(XSTR_CODE_TITLE), text);

    char hint[48];
    snprintf(hint, sizeof(hint), TX(XSTR_CODE_ENTER), code);

    char typed[8];
    const mw_err_t e = mw_screen_pin_run(title ? title : TX(XSTR_CODE_TITLE),
                                         hint, typed, sizeof(typed), false);
    if (e != MW_OK) return false;

    const bool ok = (strcmp(typed, code) == 0);
    if (!ok) mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_CODE_WRONG));
    return ok;
}
