// ---------------------------------------------------------------------------
//  On-screen keyboard: shared model + type 1 "full keyboard" (TZ 5.4).
//
//  Button semantics: keyboard_nav.h (short / long SELECT and BACK, arrow
//  auto-repeat, two arrows = layout, 4-button linear walk, dead seed letters
//  skipped). [Back] in the header is always present; Up from the top row
//  (through the candidates) focuses it.
//
//  LVGL rule: everything in this file runs on the LVGL task.
// ---------------------------------------------------------------------------
#include "keyboard.h"
#include "../crypto/memzero.h"
#include "../wallet/session.h"
#include "../config/app_config.h"

#include <stdio.h>
#include <string.h>

static bool full_live_cb(int i, void* ctx);

// ---------------------------------------------------------------------------
// Character layers. Dictionary modes only ever use the lowercase layer; the
// free-text mode (passphrase, wallet name) cycles through all four.
// ---------------------------------------------------------------------------
static const char* const KB_LAYERS[MW_KB_LAYER_COUNT] = {
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "1234567890-_=+[]{};:'\",.?/",
    "!@#$%^&*()`~<>\\| "
};

const char* mw_kb_layer_chars(mw_kb_layer_t layer) {
    if ((unsigned)layer >= MW_KB_LAYER_COUNT) layer = MW_KB_LAYER_LOWER;
    return KB_LAYERS[layer];
}

// ---------------------------------------------------------------------------
// Grid templates (task2 item 4). One character per cell, row-major; letters
// are the lowercase layer, digits mark the four command cells:
//   1 = backspace, 2 = accept / layer, 3 = previous page / space,
//   4 = next page / enter.
// The scroll keyboard always uses the ABC template: its strip is cells
// 0..25 and its special row cells 26..29 (keyboard_scroll.cpp).
// ---------------------------------------------------------------------------
static const char KB_TPL_ABC[MW_KB_GRID_CELLS + 1]    = "abcdefghijklmnopqrstuvwxyz1234";
static const char KB_TPL_QWERTY[MW_KB_GRID_CELLS + 1] = "qwertyuiop"
                                                        "asdfghjkl1"
                                                        "2zxcvbnm34";
#define KB_ABC_COLS    6
#define KB_ABC_ROWS    5
// Landscape full keyboard: the same ABC order on an 8x4 lattice (the last
// row holds y z and the four command cells), which gives wider caps than 6x5.
#define KB_ABC_WIDE_COLS 8
#define KB_ABC_WIDE_ROWS 4
#define KB_QWERTY_COLS 10
#define KB_QWERTY_ROWS 3

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------
bool mw_kb_is_dict(const mw_kb_state_t* st) {
    return st->wl != NULL;
}

void mw_kb_touch_activity(mw_kb_state_t* st) {
    st->last_activity_ms = mw_millis();
    mw_session_touch();
}

bool mw_kb_letter_live(const mw_kb_state_t* st, char c) {
    if (!mw_kb_is_dict(st)) return true;
    if (c < 'a' || c > 'z')  return false;
    return (st->next_mask & (1u << (c - 'a'))) != 0;
}

void mw_kb_refresh(mw_kb_state_t* st) {
    if (mw_kb_is_dict(st)) {
        st->cand_n = 0;
        st->cand_avail = 0;
        st->cand_total = 0;
        if (st->prefix_len == 0) {
            st->next_mask = 0x03FFFFFFu;
            st->cand_page = 0;
        } else {
            uint16_t all[MW_KB_MAX_CAND];
            int n = mw_wordlist_prefix_matches(st->wl, st->prefix, all,
                                               MW_KB_MAX_CAND, &st->cand_total);
            if (n < 0) n = 0;
            st->cand_avail = n;
            const int per = st->cand_slots > 0 ? st->cand_slots : 1;
            const int pages = (n + per - 1) / per;
            if (st->cand_page >= pages) st->cand_page = pages > 0 ? pages - 1 : 0;
            const int first = st->cand_page * per;
            for (int i = 0; i < per && first + i < n; i++) {
                st->cand[i] = all[first + i];
                st->cand_n  = i + 1;
            }
            st->next_mask = mw_wordlist_next_letters(st->wl, st->prefix);
        }
    }

    mw_kb_update_header(st);
    mw_kb_update_candidates(st);
    if (st->ctx.type == KEYBOARD_SCROLL) mw_kb_scroll_update(st);
    else                                 mw_kb_full_update(st);
}

static bool try_auto_accept(mw_kb_state_t* st) {
    if (!mw_kb_is_dict(st) || st->prefix_len == 0) return false;
    if (st->cand_total != 1) return false;
    const char* w = mw_wordlist_word(st->wl, st->cand[0]);
    if (!w || strcmp(w, st->prefix) != 0) return false;
    mw_kb_accept_candidate(st, 0);
    return true;
}

void mw_kb_input_char(mw_kb_state_t* st, char c) {
    mw_kb_touch_activity(st);

    if (mw_kb_is_dict(st)) {
        if (!mw_kb_letter_live(st, c)) return;
        if (st->prefix_len + 1u >= sizeof(st->prefix)) {
            st->at_limit = true;
            mw_kb_update_header(st);
            return;
        }
        st->at_limit = false;
        st->prefix[st->prefix_len++] = c;
        st->prefix[st->prefix_len]   = '\0';
        st->cand_page = 0;
        mw_kb_refresh(st);
        try_auto_accept(st);
        return;
    }

    if (st->text_len + 1u >= sizeof(st->text)) {
        st->at_limit = true;
        mw_kb_update_header(st);
        return;
    }
    st->at_limit = false;
    st->text[st->text_len++] = c;
    st->text[st->text_len]   = '\0';
    mw_kb_refresh(st);
}

void mw_kb_backspace(mw_kb_state_t* st) {
    mw_kb_touch_activity(st);
    st->at_limit = false;
    if (mw_kb_is_dict(st)) {
        if (st->prefix_len > 0) {
            st->prefix[--st->prefix_len] = '\0';
            st->cand_page = 0;
            mw_kb_refresh(st);
        } else if (st->ctx.allow_back) {
            mw_kb_finish(st, MW_KB_R_BACK);
        }
    } else {
        if (st->text_len > 0) {
            st->text[--st->text_len] = '\0';
            mw_kb_refresh(st);
        }
    }
}

void mw_kb_clear_prefix(mw_kb_state_t* st) {
    mw_kb_touch_activity(st);
    st->at_limit = false;
    if (mw_kb_is_dict(st)) {
        mw_memzero(st->prefix, sizeof(st->prefix));
        st->prefix_len = 0;
        st->cand_page  = 0;
    } else {
        mw_memzero(st->text, sizeof(st->text));
        st->text_len = 0;
    }
    mw_kb_refresh(st);
}

void mw_kb_clear_all(mw_kb_state_t* st) {
    mw_memzero(st->prefix, sizeof(st->prefix));
    mw_memzero(st->text, sizeof(st->text));
    st->prefix_len = 0;
    st->text_len   = 0;
    mw_kb_finish(st, MW_KB_R_RESTART);
}

void mw_kb_accept_candidate(mw_kb_state_t* st, int idx) {
    if (!mw_kb_is_dict(st) || idx < 0 || idx >= st->cand_n) return;
    const char* w = mw_wordlist_word(st->wl, st->cand[idx]);
    if (!w) return;
    if (st->out && st->out_cap > 0) {
        strncpy(st->out, w, st->out_cap - 1);
        st->out[st->out_cap - 1] = '\0';
    }
    mw_kb_finish(st, MW_KB_R_OK);
}

void mw_kb_finish(mw_kb_state_t* st, int result) {
    if (st->timeout_timer) {
        MW_TIMER_DEL(st->timeout_timer);
        st->timeout_timer = NULL;
    }
    mw_ui_set_button_hook(NULL, NULL);

    if (result == MW_KB_R_OK && !mw_kb_is_dict(st) && st->out && st->out_cap) {
        strncpy(st->out, st->text, st->out_cap - 1);
        st->out[st->out_cap - 1] = '\0';
    }

    mw_ui_page_destroy(&st->page);

    mw_memzero(st->text, sizeof(st->text));
    mw_memzero(st->prefix, sizeof(st->prefix));
    st->text_len         = 0;
    st->prefix_len       = 0;
    mw_kn_reset(&st->nav);

    mw_ui_modal_done(result);
}

// ---------------------------------------------------------------------------
// Shared view
// ---------------------------------------------------------------------------
static void kb_close_cb(lv_event_t* e) {
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    if (st->ctx.allow_back) mw_kb_finish(st, MW_KB_R_BACK);
    else                    mw_kb_finish(st, MW_KB_R_CANCEL);
}
static void kb_cand_cb(lv_event_t* e) {
    lv_obj_t* btn = MW_EVT_OBJ(e);
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    for (int i = 0; i < st->cand_slots; i++) {
        if (st->cand_btn[i] == btn) { mw_kb_accept_candidate(st, i); return; }
    }
}
static void kb_key_cb(lv_event_t* e) {
    lv_obj_t* btn = MW_EVT_OBJ(e);
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    for (int i = 0; i < st->key_n; i++) {
        if (st->key_btn[i] == btn) { mw_kb_cell_activate(st, i); return; }
    }
}
static void kb_escape(void* user) {
    mw_kb_finish((mw_kb_state_t*)user, MW_KB_R_CANCEL);
}

static void kb_timeout_cb(lv_timer_t* t) {
    mw_kb_state_t* st = (mw_kb_state_t*)MW_TIMER_USER(t);
    if (!st) return;
    if (mw_millis() - st->last_activity_ms < MW_INPUT_TIMEOUT_MS) return;
    mw_session_wipe_input();
    mw_kb_clear_all(st);
}

void mw_kb_focus(mw_kb_state_t* st, lv_obj_t* obj) {
    if (obj && st->page.group) lv_group_focus_obj(obj);
}

// Width of an ASCII string in `font` (glyph advances, no kerning).
static int32_t text_px(const lv_font_t* font, const char* s, size_t n) {
    int32_t w = 0;
    for (size_t i = 0; i < n; i++) {
        w += (int32_t)lv_font_get_glyph_width(font, (uint8_t)s[i],
                                              (i + 1 < n) ? (uint8_t)s[i + 1] : 0);
    }
    return w;
}

// Typed-text line. It always shows the END of the text: when "caption: text_"
// does not fit, the caption goes and the line becomes "..." plus the last
// characters that fit, so the character just typed is always visible.
static void set_typed_line(mw_kb_state_t* st, const char* caption, const char* typed) {
    const mw_metrics_t* m = mw_metrics();
    const lv_font_t* font = m->font_mono;
    int32_t avail = lv_obj_get_content_width(st->lbl_prefix);
    if (avail <= 0) avail = (int32_t)(m->w - 2 * m->pad);

    char buf[MW_KB_TEXT_MAX + 48];
    snprintf(buf, sizeof(buf), "%s: %s_", caption, typed);
    if (text_px(font, buf, strlen(buf)) > avail) {
        const size_t tl = strlen(typed);
        const int32_t room = avail - text_px(font, "..._", 4);
        size_t start = tl;
        int32_t w = 0;
        while (start > 0) {
            const int32_t g = (int32_t)lv_font_get_glyph_width(
                font, (uint8_t)typed[start - 1], (uint8_t)typed[start]);
            if (w + g > room) break;
            w += g;
            start--;
        }
        snprintf(buf, sizeof(buf), "...%s_", typed + start);
    }
    lv_label_set_text(st->lbl_prefix, buf);
    mw_memzero(buf, sizeof(buf));
}

void mw_kb_update_header(mw_kb_state_t* st) {
    const char* typed = mw_kb_is_dict(st) ? st->prefix : st->text;

    if (st->lbl_word) {
        if (st->at_limit) {
            lv_label_set_text(st->lbl_word, TX(XSTR_INPUT_LIMIT));
            lv_obj_set_style_text_color(st->lbl_word, mw_palette()->danger,
                                        LV_PART_MAIN);
        } else if (st->ctx.highlight && st->ctx.word_total > 0) {
            lv_label_set_text_fmt(st->lbl_word, TX(XSTR_SEED_FIX_WORD),
                                  st->ctx.word_index);
            lv_obj_set_style_text_color(st->lbl_word, mw_palette()->danger,
                                        LV_PART_MAIN);
        } else {
            lv_obj_set_style_text_color(st->lbl_word, mw_palette()->text_dim,
                                        LV_PART_MAIN);
            if (st->ctx.word_total > 0) {
                lv_label_set_text_fmt(st->lbl_word, T(STR_WORD_OF),
                                      st->ctx.word_index, st->ctx.word_total);
            } else {
                lv_label_set_text(st->lbl_word,
                                  st->ctx.title ? st->ctx.title
                                                : T(STR_PASSPHRASE));
            }
        }
    }
    if (st->lbl_prefix) {
        // task2 item 7: say what the line IS instead of "Prefix". Dictionary
        // mode collects the start of a seed word; free-text mode collects the
        // value named by the screen title ("Wallet name", "Passphrase", ...).
        const char* caption = mw_kb_is_dict(st) ? TX(XSTR_WORD_START)
                                                : TX(XSTR_INPUT);
        set_typed_line(st, caption, typed);
    }
}

void mw_kb_update_candidates(mw_kb_state_t* st) {
    if (!st->cand_cont) return;
    for (int i = 0; i < st->cand_slots; i++) {
        lv_obj_t* b = st->cand_btn[i];
        if (!b) continue;
        lv_obj_t* l = lv_obj_get_child(b, 0);
        if (i < st->cand_n) {
            const char* w = mw_wordlist_word(st->wl, st->cand[i]);
            if (l) lv_label_set_text(l, w ? w : "");
            MW_OBJ_CLEAR_FLAG(b, LV_OBJ_FLAG_HIDDEN);
        } else {
            if (l) lv_label_set_text(l, "");
            lv_obj_add_flag(b, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

void mw_kb_ok(mw_kb_state_t* st) {
    if (!st) return;
    if (mw_kb_is_dict(st)) {
        if (st->cand_n > 0) mw_kb_accept_candidate(st, 0);
    } else {
        mw_kb_finish(st, MW_KB_R_OK);
    }
}

static void kb_ok_cb(lv_event_t* e) {
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    if (!st) return;
    mw_kb_touch_activity(st);
    mw_kb_ok(st);
}

static lv_obj_t* head_button(mw_kb_state_t* st, lv_obj_t* parent, const char* text,
                             lv_coord_t w, lv_event_cb_t cb) {
    lv_obj_t* b = MW_BTN_CREATE(parent);
    mw_theme_button_fixed(b, w, mw_metrics()->bar_h);
    lv_obj_add_flag(b, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_t* l = lv_label_create(b);
    lv_label_set_text(l, text);
    lv_obj_center(l);
    lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, st);
    mw_ui_focus_add(&st->page, b);
    return b;
}

// Header row [Back] [caption / word counter] [OK], the typed-text line on
// its own full-width row, then the candidate grid in dictionary modes. There
// is no footer: Done is the accept / enter key cap.
void mw_kb_build_frame(mw_kb_state_t* st) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* root = st->page.body;

    // Touch slack around [<] and [OK]. The keys keep their size, but their
    // hit area reaches up to the screen edge (the body's top padding is
    // moved into the header) and a few pixels down towards the typed line:
    // a finger aimed at a 28 px key at the very top of the glass is often
    // reported just outside it. The header row carries that slack as its
    // own padding, because LVGL only looks for a child under the finger
    // inside the parent's area.
    const lv_coord_t ext_top = m->touch ? m->pad : 0;
    lv_coord_t ext_bot = 0;
    if (m->touch) {
        ext_bot = (lv_coord_t)(m->bar_h / 5);
        if (ext_bot < 4) ext_bot = 4;
    }
    if (ext_top > 0) lv_obj_set_style_pad_top(root, 0, LV_PART_MAIN);

    lv_obj_t* head = lv_obj_create(root);
    lv_obj_remove_style_all(head);
    lv_obj_set_width(head, lv_pct(100));
    lv_obj_set_height(head, (lv_coord_t)(m->bar_h + ext_top + ext_bot));
    lv_obj_set_style_pad_top(head, ext_top, LV_PART_MAIN);
    lv_obj_set_style_pad_bottom(head, ext_bot, LV_PART_MAIN);
    lv_obj_set_flex_flow(head, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(head, LV_FLEX_ALIGN_START,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(head, m->gap, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(head, LV_OBJ_FLAG_SCROLLABLE);

    // Always present, on every resolution: the on-screen [Back] key is the
    // only way to step one level up when the physical Back key is missing or
    // remapped by the host, and it is part of the navigation grid on every
    // layout (Up from the top row focuses it).
    // Icons, not words. [<] and [OK] are wide targets (twice the old 4/3
    // bar_h), but never so wide that the caption between them gets less
    // than a third of the row.
    lv_coord_t icon_w = (lv_coord_t)(2 * (m->bar_h + m->bar_h / 3));
    {
        const lv_coord_t row_w = (lv_coord_t)(m->w - 2 * m->pad);
        const lv_coord_t cap   = (lv_coord_t)((row_w - 2 * m->gap) / 3);
        if (icon_w > cap) icon_w = cap;
        if (icon_w < m->bar_h) icon_w = m->bar_h;
    }
    st->btn_back = head_button(st, head, LV_SYMBOL_LEFT, icon_w, kb_close_cb);
    const lv_coord_t ext = (ext_top > ext_bot) ? ext_top : ext_bot;
    if (ext > 0) lv_obj_set_ext_click_area(st->btn_back, ext);

    st->lbl_word = lv_label_create(head);
    lv_obj_add_style(st->lbl_word, mw_style_dim(), LV_PART_MAIN);
    // Caption or word counter: up to two lines when the header has room.
    lv_label_set_long_mode(st->lbl_word, LV_LABEL_LONG_DOT);
    lv_obj_set_width(st->lbl_word, 0);
    {
        const lv_coord_t lh = (lv_coord_t)lv_font_get_line_height(m->font_small);
        lv_obj_set_height(st->lbl_word, (lv_coord_t)(m->bar_h >= 2 * lh ? 2 * lh : lh));
    }
    lv_obj_set_flex_grow(st->lbl_word, 1);
    lv_obj_set_style_text_align(st->lbl_word, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_label_set_text(st->lbl_word, "");

    // No [Clear] key: the backspace key cap deletes, long Back cancels.

    // [OK]: finish the input (free text) or take the first candidate (seed
    // words), same as the accept / enter key cap.
    st->btn_ok = head_button(st, head, LV_SYMBOL_OK, icon_w, kb_ok_cb);
    if (ext > 0) lv_obj_set_ext_click_area(st->btn_ok, ext);

    st->lbl_prefix = lv_label_create(root);
    lv_obj_add_style(st->lbl_prefix, mw_style_mono(), LV_PART_MAIN);
    lv_label_set_long_mode(st->lbl_prefix, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(st->lbl_prefix, lv_pct(100));
    lv_label_set_text(st->lbl_prefix, "");

    st->cand_slots = 0;
    if (mw_kb_is_dict(st)) {
        const int slots = m->cand_cols * m->cand_rows;
        st->cand_cont = lv_obj_create(root);
        lv_obj_remove_style_all(st->cand_cont);
        lv_obj_set_width(st->cand_cont, lv_pct(100));
        lv_obj_set_height(st->cand_cont,
                          (lv_coord_t)(m->cand_rows * m->cand_h +
                                       (m->cand_rows - 1) * m->gap));
        lv_obj_set_flex_flow(st->cand_cont, LV_FLEX_FLOW_ROW_WRAP);
        lv_obj_set_style_pad_row(st->cand_cont, m->gap, LV_PART_MAIN);
        lv_obj_set_style_pad_column(st->cand_cont, m->gap, LV_PART_MAIN);
        MW_OBJ_CLEAR_FLAG(st->cand_cont, LV_OBJ_FLAG_SCROLLABLE);

        const lv_coord_t cw = (lv_coord_t)((m->w - 2 * m->pad -
                                            (m->cand_cols - 1) * m->gap) /
                                           m->cand_cols);
        for (int i = 0; i < slots && i < MW_KB_MAX_CAND; i++) {
            lv_obj_t* b = MW_BTN_CREATE(st->cand_cont);
            mw_theme_button_fixed(b, cw, m->cand_h);
            lv_obj_set_style_bg_color(b, mw_palette()->surface2, LV_PART_MAIN);
            lv_obj_add_flag(b, LV_OBJ_FLAG_EVENT_BUBBLE);
            lv_obj_t* l = lv_label_create(b);
            lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
            lv_obj_set_width(l, lv_pct(100));
            lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            lv_label_set_text(l, "");
            lv_obj_center(l);
            lv_obj_add_event_cb(b, kb_cand_cb, LV_EVENT_CLICKED, st);
            mw_ui_focus_add(&st->page, b);
            st->cand_btn[i] = b;
            st->cand_slots  = i + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Cells
// ---------------------------------------------------------------------------
static uint8_t cmd_for_marker(char marker, bool dict) {
    switch (marker) {
    case '1': return MW_KC_BKSP;
    case '2': return dict ? MW_KC_ACCEPT : MW_KC_LAYER;
    case '3': return dict ? MW_KC_PREV   : MW_KC_SPACE;
    case '4': return dict ? MW_KC_NEXT   : MW_KC_ENTER;
    default:  return MW_KC_NONE;
    }
}

void mw_kb_fill_cells(mw_kb_state_t* st) {
    const bool dict = mw_kb_is_dict(st);
    // task2 item 4: QWERTY on the touch (full) keyboard when the setting says
    // so; the scroll keyboard keeps the alphabet, its strip is 0..25.
    st->qwerty = (st->ctx.type != KEYBOARD_SCROLL) &&
                 (mw_ui_settings()->kb_layout == KB_LAYOUT_QWERTY);
    const char* tpl = st->qwerty ? KB_TPL_QWERTY : KB_TPL_ABC;
    if (st->qwerty) {
        st->cols = KB_QWERTY_COLS; st->rows = KB_QWERTY_ROWS;
    } else if (st->ctx.type != KEYBOARD_SCROLL && mw_metrics()->landscape) {
        st->cols = KB_ABC_WIDE_COLS; st->rows = KB_ABC_WIDE_ROWS;
    } else {
        st->cols = KB_ABC_COLS; st->rows = KB_ABC_ROWS;
    }

    const mw_kb_layer_t layer = dict ? MW_KB_LAYER_LOWER : st->layer;
    // Symbol layers are laid over the letter cells in template order, so the
    // digit row of SYM1 lands on the top row of the QWERTY grid.
    const char* sym = (layer == MW_KB_LAYER_SYM1 || layer == MW_KB_LAYER_SYM2)
                          ? KB_LAYERS[layer] : NULL;
    int si = 0;

    memset(st->key_ch, 0, sizeof(st->key_ch));
    memset(st->key_cmd, 0, sizeof(st->key_cmd));

    for (int i = 0; i < MW_KB_GRID_CELLS; i++) {
        const char t = tpl[i];
        if (t >= '1' && t <= '4') {
            st->key_ch[i]  = 0;
            st->key_cmd[i] = cmd_for_marker(t, dict);
            continue;
        }
        st->key_cmd[i] = MW_KC_NONE;
        if (sym) {
            st->key_ch[i] = sym[si] ? sym[si] : 0;
            if (sym[si]) si++;
        } else if (layer == MW_KB_LAYER_UPPER) {
            st->key_ch[i] = (char)(t - 'a' + 'A');
        } else {
            st->key_ch[i] = t;
        }
    }
    st->key_n = MW_KB_GRID_CELLS;
}

// Space has its own caption: '_' is a real character on the 12# layer.
#define KB_SPACE_CAP "|_|"

void mw_kb_key_label(mw_kb_state_t* st, int cell, char* buf, size_t cap) {
    if (cell < 0 || cell >= MW_KB_GRID_CELLS || cap == 0) { if (cap) buf[0] = 0; return; }
    switch (st->key_cmd[cell]) {
    case MW_KC_BKSP:   snprintf(buf, cap, "%s", LV_SYMBOL_BACKSPACE); return;
    case MW_KC_ACCEPT: snprintf(buf, cap, "%s", LV_SYMBOL_OK);        return;
    case MW_KC_LAYER:  snprintf(buf, cap, "%s", LV_SYMBOL_KEYBOARD);  return;
    case MW_KC_PREV:   snprintf(buf, cap, "%s", LV_SYMBOL_LEFT);      return;
    case MW_KC_NEXT:   snprintf(buf, cap, "%s", LV_SYMBOL_RIGHT);     return;
    case MW_KC_SPACE:  snprintf(buf, cap, "%s", KB_SPACE_CAP);        return;
    case MW_KC_ENTER:  snprintf(buf, cap, "%s", LV_SYMBOL_NEW_LINE);  return;
    default: break;
    }
    if (st->key_ch[cell] == ' ') snprintf(buf, cap, "%s", KB_SPACE_CAP);
    else if (st->key_ch[cell])   snprintf(buf, cap, "%c", st->key_ch[cell]);
    else                         buf[0] = '\0';
}

void mw_kb_cell_activate(mw_kb_state_t* st, int cell) {
    if (cell < 0 || cell >= st->key_n) return;
    mw_kb_touch_activity(st);

    switch (st->key_cmd[cell]) {
    case MW_KC_BKSP:   mw_kb_backspace(st); return;
    case MW_KC_ACCEPT: if (st->cand_n > 0) mw_kb_accept_candidate(st, 0); return;
    case MW_KC_ENTER:  mw_kb_finish(st, MW_KB_R_OK); return;
    case MW_KC_SPACE:  mw_kb_input_char(st, ' '); return;
    case MW_KC_LAYER:
        st->layer = (mw_kb_layer_t)((st->layer + 1) % MW_KB_LAYER_COUNT);
        mw_kb_fill_cells(st);
        mw_kb_refresh(st);
        return;
    case MW_KC_PREV:
        if (st->prefix_len == 0 && st->ctx.allow_back) {
            mw_kb_finish(st, MW_KB_R_BACK);
        } else if (st->cand_page > 0) {
            st->cand_page--;
            mw_kb_refresh(st);
        }
        return;
    case MW_KC_NEXT: {
        const int per = st->cand_slots > 0 ? st->cand_slots : 1;
        if ((st->cand_page + 1) * per < st->cand_avail) {
            st->cand_page++;
            mw_kb_refresh(st);
        }
        return;
    }
    default: break;
    }
    if (st->key_ch[cell]) mw_kb_input_char(st, st->key_ch[cell]);
}

lv_obj_t* mw_kb_make_key(mw_kb_state_t* st, lv_obj_t* parent, int cell,
                         lv_coord_t w, lv_coord_t h) {
    lv_obj_t* b = MW_BTN_CREATE(parent);
    lv_obj_remove_style_all(b);
    lv_obj_add_style(b, mw_style_key(), LV_PART_MAIN);
    lv_obj_add_style(b, mw_style_focus(), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_add_style(b, mw_style_pressed(), LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_size(b, w, h);
    lv_obj_add_flag(b, LV_OBJ_FLAG_EVENT_BUBBLE);
    MW_OBJ_CLEAR_FLAG(b, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* l = lv_label_create(b);
    lv_obj_set_style_text_font(l, mw_metrics()->font_body, LV_PART_MAIN);
    lv_label_set_text(l, "");
    lv_obj_center(l);

    lv_obj_add_event_cb(b, kb_key_cb, LV_EVENT_CLICKED, st);
    mw_ui_focus_add(&st->page, b);

    st->key_btn[cell] = b;
    st->key_lbl[cell] = l;
    return b;
}

void mw_kb_paint_cells(mw_kb_state_t* st) {
    char buf[8];
    for (int i = 0; i < st->key_n; i++) {
        if (!st->key_btn[i]) continue;
        mw_kb_key_label(st, i, buf, sizeof(buf));
        if (st->key_lbl[i]) lv_label_set_text(st->key_lbl[i], buf);

        const bool live = (st->key_cmd[i] != MW_KC_NONE) ||
                          (st->key_ch[i] != 0 && mw_kb_letter_live(st, st->key_ch[i]));
        if (live) {
            lv_obj_remove_style(st->key_btn[i], mw_style_key_dead(), LV_PART_MAIN);
            lv_obj_add_flag(st->key_btn[i], LV_OBJ_FLAG_CLICKABLE);
        } else {
            lv_obj_add_style(st->key_btn[i], mw_style_key_dead(), LV_PART_MAIN);
            MW_OBJ_CLEAR_FLAG(st->key_btn[i], LV_OBJ_FLAG_CLICKABLE);
        }
    }
}

// ---------------------------------------------------------------------------
// Type 1: full keyboard
// ---------------------------------------------------------------------------
// The key grid takes the room the header, the typed line and the candidates
// leave: that height is measured first, then the caps get kw = width / cols
// and kh = room / rows (at most 1.5x kw). The caps sit in a ROW_WRAP
// container exactly cols*kw wide, so the shape cannot change; a spacer above
// keeps the grid at the bottom edge.
void mw_kb_full_build(mw_kb_state_t* st) {
    const mw_metrics_t* m = mw_metrics();
    mw_kb_fill_cells(st);

    const lv_coord_t room    = mw_ui_free_height(st->page.body);
    const lv_coord_t inner_w = (lv_coord_t)lv_obj_get_content_width(st->page.body);
    lv_coord_t kw = (lv_coord_t)(inner_w / st->cols);
    if (kw < 8) kw = 8;
    const lv_coord_t kh_min = m->compact ? 8
                            : (lv_coord_t)(lv_font_get_line_height(m->font_body) + 4);
    // The spacer costs one more row gap.
    lv_coord_t kh = (lv_coord_t)((room - m->gap) / st->rows);
    if (kh > kw * 3 / 2) kh = (lv_coord_t)(kw * 3 / 2);
    if (kh < kh_min) kh = kh_min;

    lv_obj_t* spacer = lv_obj_create(st->page.body);
    lv_obj_remove_style_all(spacer);
    lv_obj_set_size(spacer, lv_pct(100), 0);
    lv_obj_set_flex_grow(spacer, 1);
    MW_OBJ_CLEAR_FLAG(spacer, LV_OBJ_FLAG_SCROLLABLE);

    st->keys_cont = lv_obj_create(st->page.body);
    lv_obj_remove_style_all(st->keys_cont);
    lv_obj_set_size(st->keys_cont, lv_pct(100), (lv_coord_t)(st->rows * kh));
    MW_OBJ_CLEAR_FLAG(st->keys_cont, LV_OBJ_FLAG_SCROLLABLE);

    const lv_coord_t side = (lv_coord_t)(inner_w - st->cols * kw);
    lv_obj_set_flex_flow(st->keys_cont, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_left(st->keys_cont, (lv_coord_t)(side / 2), LV_PART_MAIN);
    lv_obj_set_style_pad_right(st->keys_cont, (lv_coord_t)(side - side / 2), LV_PART_MAIN);
    lv_obj_set_style_pad_row(st->keys_cont, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_column(st->keys_cont, 0, LV_PART_MAIN);

    for (int i = 0; i < MW_KB_GRID_CELLS; i++) {
        mw_kb_make_key(st, st->keys_cont, i, kw, kh);
    }

    st->area    = MW_KB_AREA_KEYS;
    st->cur_row = 0;
    st->cur_col = 0;
}

void mw_kb_full_update(mw_kb_state_t* st) {
    mw_kb_paint_cells(st);
    // The letter under the button cursor may have just gone dead (the
    // prefix grew): move on to the next live cell.
    if (st->area == MW_KB_AREA_KEYS && st->key_n > 0) {
        const int cur = st->cur_row * st->cols + st->cur_col;
        if (!mw_kb_cell_live(st, cur)) {
            const int t = mw_kn_linear_step(st->key_n, cur, 1, full_live_cb, st);
            st->cur_row = t / st->cols;
            st->cur_col = t % st->cols;
        }
    }
}

static void full_focus_current(mw_kb_state_t* st) {
    const mw_metrics_t* m = mw_metrics();
    if (st->area == MW_KB_AREA_HEADER) {
        lv_obj_t* h = (st->head_col == 1 && st->btn_ok) ? st->btn_ok : st->btn_back;
        if (h) mw_kb_focus(st, h);
        return;
    }
    if (st->area == MW_KB_AREA_CAND) {
        int idx = st->cur_row * m->cand_cols + st->cur_col;
        if (idx >= st->cand_slots) idx = st->cand_slots - 1;
        if (idx >= 0) mw_kb_focus(st, st->cand_btn[idx]);
    } else {
        int idx = st->cur_row * st->cols + st->cur_col;
        if (idx >= st->key_n) idx = st->key_n - 1;
        if (idx >= 0 && st->key_btn[idx]) {
            mw_kb_focus(st, st->key_btn[idx]);
            lv_obj_scroll_to_view(st->key_btn[idx], LV_ANIM_OFF);
        }
    }
}

bool mw_kb_cell_live(const mw_kb_state_t* st, int cell) {
    if (!st || cell < 0 || cell >= st->key_n) return false;
    if (st->key_cmd[cell] != MW_KC_NONE) return true;
    return st->key_ch[cell] != 0 && mw_kb_letter_live(st, st->key_ch[cell]);
}

int mw_kb_layer_cell(const mw_kb_state_t* st) {
    for (int i = 0; st && i < st->key_n; i++)
        if (st->key_cmd[i] == MW_KC_LAYER) return i;
    return -1;
}

static bool full_live_cb(int i, void* ctx) {
    return mw_kb_cell_live((const mw_kb_state_t*)ctx, i);
}

// ---- four-button boards: one list of every focusable item ----------------
// [Back] (if any) - the candidates on this page - the key cells.
static int full_head_n(const mw_kb_state_t* st) {
    return (st->btn_back ? 1 : 0) + (st->btn_ok ? 1 : 0);
}

static int full_lin_count(const mw_kb_state_t* st) {
    return full_head_n(st) + st->cand_n + st->key_n;
}

static int full_lin_index(const mw_kb_state_t* st) {
    const mw_metrics_t* m = mw_metrics();
    const int head = full_head_n(st);
    switch (st->area) {
    case MW_KB_AREA_HEADER: return (st->head_col == 1 && st->btn_ok && st->btn_back) ? 1 : 0;
    case MW_KB_AREA_CAND:   return head + st->cur_row * m->cand_cols + st->cur_col;
    default:                return head + st->cand_n + st->cur_row * st->cols + st->cur_col;
    }
}

static bool full_lin_live(int i, void* ctx) {
    const mw_kb_state_t* st = (const mw_kb_state_t*)ctx;
    const int head = full_head_n(st);
    if (i < head) return true;
    i -= head;
    if (i < st->cand_n) return true;
    return mw_kb_cell_live(st, i - st->cand_n);
}

static void full_lin_set(mw_kb_state_t* st, int i) {
    const mw_metrics_t* m = mw_metrics();
    const int head = full_head_n(st);
    if (i < head) {
        st->area = MW_KB_AREA_HEADER;
        st->head_col = (st->btn_back && i == 0) ? 0 : 1;
        return;
    }
    i -= head;
    if (i < st->cand_n) {
        st->area    = MW_KB_AREA_CAND;
        st->cur_row = i / m->cand_cols;
        st->cur_col = i % m->cand_cols;
        return;
    }
    i -= st->cand_n;
    st->area    = MW_KB_AREA_KEYS;
    st->cur_row = i / st->cols;
    st->cur_col = i % st->cols;
}

// One step of the cursor in the 2-D layout (six buttons / encoder).
static void full_move_2d(mw_kb_state_t* st, mw_button_t b) {
    const mw_metrics_t* m = mw_metrics();
    if (st->area == MW_KB_AREA_HEADER) {
        if (b == MW_BTN_LEFT && st->btn_back)  st->head_col = 0;
        if (b == MW_BTN_RIGHT && st->btn_ok)   st->head_col = 1;
        if (b == MW_BTN_DOWN) {
            st->area = MW_KB_AREA_KEYS;
            const int first = mw_kn_linear_step(st->key_n, st->key_n - 1, 1, full_live_cb, st);
            st->cur_row = first / st->cols;
            st->cur_col = first % st->cols;
        }
        return;
    }
    if (st->area == MW_KB_AREA_CAND) {
        const int cols = m->cand_cols;
        int idx = st->cur_row * cols + st->cur_col;
        switch (b) {
        case MW_BTN_LEFT:  if (idx > 0) idx--; break;
        case MW_BTN_RIGHT: if (idx < st->cand_n - 1) idx++; break;
        case MW_BTN_UP:
            if (idx >= cols) idx -= cols;
            else if (st->btn_back) { st->area = MW_KB_AREA_HEADER; st->head_col = 0; return; }
            break;
        case MW_BTN_DOWN:
            if (idx + cols < st->cand_n) idx += cols;
            else { st->area = MW_KB_AREA_KEYS; st->cur_row = 0;
                   if (!mw_kb_cell_live(st, st->cur_col)) {
                       const int t = mw_kn_grid_step(st->key_n, st->cols, st->cur_col,
                                                     MW_BTN_RIGHT, full_live_cb, st);
                       st->cur_col = t % st->cols; st->cur_row = t / st->cols;
                   }
                   return; }
            break;
        default: break;
        }
        st->cur_row = idx / cols;
        st->cur_col = idx % cols;
        return;
    }
    // Keys.
    const int cur = st->cur_row * st->cols + st->cur_col;
    const int t = mw_kn_grid_step(st->key_n, st->cols, cur, b, full_live_cb, st);
    if (t >= 0) {
        st->cur_row = t / st->cols;
        st->cur_col = t % st->cols;
    } else if (st->cand_n > 0) {                       // up out of the top row
        st->area    = MW_KB_AREA_CAND;
        st->cur_row = (st->cand_n - 1) / m->cand_cols;
        if (st->cur_col >= m->cand_cols) st->cur_col = m->cand_cols - 1;
        if (st->cur_row * m->cand_cols + st->cur_col >= st->cand_n)
            st->cur_col = (st->cand_n - 1) % m->cand_cols;
    } else if (st->btn_back) {
        st->area = MW_KB_AREA_HEADER;
        st->head_col = 0;
    }
}

bool mw_kb_full_button(mw_kb_state_t* st, mw_button_t b, uint32_t hold_ms,
                       bool released) {
    const mw_metrics_t* m = mw_metrics();
    const mw_kn_out_t o = mw_kn_event(&st->nav, b, hold_ms, released, mw_millis());
    if (o.act == MW_KN_NONE) return true;
    mw_kb_touch_activity(st);

    switch (o.act) {
    case MW_KN_MOVE:
        st->prev_area = st->area;
        st->prev_row  = st->cur_row;
        st->prev_col  = st->cur_col;
        if (st->linear) {
            if (o.dir == MW_BTN_UP || o.dir == MW_BTN_DOWN ||
                o.dir == MW_BTN_LEFT || o.dir == MW_BTN_RIGHT) {
                const int d = (o.dir == MW_BTN_UP || o.dir == MW_BTN_LEFT) ? -1 : 1;
                full_lin_set(st, mw_kn_linear_step(full_lin_count(st), full_lin_index(st), d,
                                                   full_lin_live, st));
            }
        } else {
            full_move_2d(st, o.dir);
        }
        break;
    case MW_KN_LAYOUT: {
        if (o.undo_move) {
            st->area    = st->prev_area;
            st->cur_row = st->prev_row;
            st->cur_col = st->prev_col;
        }
        const int lc = mw_kb_layer_cell(st);
        if (lc >= 0) mw_kb_cell_activate(st, lc);
        break;
    }
    case MW_KN_ACTIVATE:
        if (st->area == MW_KB_AREA_HEADER) {
            if (st->head_col == 1 && st->btn_ok) mw_kb_ok(st);
            else mw_kb_finish(st, st->ctx.allow_back ? MW_KB_R_BACK : MW_KB_R_CANCEL);
            return true;
        }
        if (st->area == MW_KB_AREA_CAND) {
            mw_kb_accept_candidate(st, st->cur_row * m->cand_cols + st->cur_col);
        } else {
            mw_kb_cell_activate(st, st->cur_row * st->cols + st->cur_col);
        }
        return true;
    case MW_KN_FINISH:
        mw_kb_finish(st, MW_KB_R_OK);
        return true;
    case MW_KN_BACKSPACE:
        mw_kb_backspace(st);
        return true;
    case MW_KN_CANCEL:
        mw_kb_finish(st, st->ctx.allow_back ? MW_KB_R_BACK : MW_KB_R_CANCEL);
        return true;
    default:
        return true;
    }

    full_focus_current(st);
    return true;
}

// ===========================================================================
//  mw_kb_run() - the only public entry point (ui.h)
// ===========================================================================
static mw_kb_state_t s_kb;

static void kb_cancel_now(void) { mw_kb_finish(&s_kb, MW_KB_R_CANCEL); }

static bool kb_btn_hook(mw_button_t b, uint32_t hold_ms, bool released,
                        void* user) {
    mw_kb_state_t* st = (mw_kb_state_t*)user;
    if (!st || !st->page.scr) return false;
    if (st->ctx.type == KEYBOARD_SCROLL) {
        return mw_kb_scroll_button(st, b, hold_ms, released);
    }
    return mw_kb_full_button(st, b, hold_ms, released);
}

static void kb_build_job(void* arg) {
    mw_kb_state_t* st = (mw_kb_state_t*)arg;

    mw_kn_reset(&st->nav);
    st->btn_back          = NULL;
    st->btn_ok            = NULL;
    st->head_col          = 0;
    // Four-button boards (no LEFT/RIGHT): UP / DOWN walk everything.
    {
        const uint32_t lr = (1u << MW_BTN_LEFT) | (1u << MW_BTN_RIGHT);
        st->linear = (mw_buttons_present() & lr) != lr;
    }

    mw_ui_page_create(&st->page, NULL, false);
    mw_ui_page_set_escape(&st->page, kb_escape, st);

    mw_kb_build_frame(st);
    if (st->ctx.type == KEYBOARD_SCROLL) mw_kb_scroll_build(st);
    else                                 mw_kb_full_build(st);

    mw_kb_refresh(st);
    if (st->ctx.type != KEYBOARD_SCROLL) full_focus_current(st);

    mw_ui_set_button_hook(kb_btn_hook, st);
    st->timeout_timer = lv_timer_create(kb_timeout_cb, 1000, st);
    // Autolock closes the keyboard like Cancel does (task 3).
    mw_ui_modal_set_cancel(kb_cancel_now);
}

mw_err_t mw_kb_run(const mw_kb_ctx_t* ctx, char* out, size_t out_cap) {
    if (!ctx || !out || out_cap == 0) return MW_ERR_INVALID_ARG;

    memset(&s_kb, 0, sizeof(s_kb));
    s_kb.ctx     = *ctx;
    s_kb.out     = out;
    s_kb.out_cap = out_cap;
    out[0] = '\0';

    switch (ctx->mode) {
    case MW_KB_MODE_SEED_LEGACY:   s_kb.wl = mw_wordlist(MW_WL_MONERO_EN);   break;
    case MW_KB_MODE_SEED_POLYSEED: s_kb.wl = mw_wordlist(MW_WL_POLYSEED_EN); break;
    case MW_KB_MODE_FREE_TEXT:
    default:                       s_kb.wl = NULL;                          break;
    }

    if (s_kb.ctx.type != KEYBOARD_FULL && s_kb.ctx.type != KEYBOARD_SCROLL) {
        s_kb.ctx.type = mw_ui_settings()->keyboard;
    }
    s_kb.layer            = MW_KB_LAYER_LOWER;
    s_kb.next_mask        = 0x03FFFFFFu;
    s_kb.last_activity_ms = mw_millis();

    const int32_t r = mw_ui_modal_call(kb_build_job, &s_kb);

    mw_memzero(s_kb.text, sizeof(s_kb.text));
    mw_memzero(s_kb.prefix, sizeof(s_kb.prefix));

    switch (r) {
    case MW_KB_R_OK:      return MW_OK;
    case MW_KB_R_BACK:    return MW_KB_BACK;
    case MW_KB_R_RESTART: return MW_KB_RESTART;
    default:              return MW_ERR_ABORTED;
    }
}