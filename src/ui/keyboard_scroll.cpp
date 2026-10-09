// ---------------------------------------------------------------------------
//  On-screen keyboard: type 2 "scroll keyboard" (TZ 5.4).
//
//  The model, the candidate logic and the cell semantics live in
//  keyboard_full.cpp and are shared verbatim.
//
//  Button semantics: keyboard_nav.h. In the letter strip LEFT / RIGHT (and,
//  on 4-button boards, UP / DOWN) step through the live letters; the strip
//  already skips letters that cannot continue a seed word.
//
//  On startup the LVGL focus is moved onto the first letter, not on the
//  header [Back] button: LVGL auto-focuses the first object added to the
//  group, which would otherwise be the header button.
// ---------------------------------------------------------------------------
#include "keyboard.h"

#include <string.h>

// Cells 0..25 live in the strip, cells 26..29 in the special row.
#define SCROLL_SPECIAL_FIRST 26

static void scroll_left_cb(lv_event_t* e);
static void scroll_right_cb(lv_event_t* e);
static void scroll_focus_current(mw_kb_state_t* st);

// ---------------------------------------------------------------------------
static lv_coord_t strip_avail(const mw_metrics_t* m) {
    const lv_coord_t arrows = (lv_coord_t)(2 * m->row_h);
    lv_coord_t avail = (lv_coord_t)(m->w - 2 * m->pad - arrows - 2 * m->gap);
    if (avail < m->scroll_visible) avail = m->scroll_visible;
    return avail;
}

// Gap between two caps of the strip.
static lv_coord_t strip_gap(const mw_metrics_t* m) { return m->mono ? 1 : 2; }

// Width of n caps with their gaps fitting the strip.
static lv_coord_t strip_cap_for(const mw_metrics_t* m, uint8_t n) {
    return (lv_coord_t)((strip_avail(m) - (n - 1) * strip_gap(m)) / n);
}

static uint8_t strip_visible(const mw_metrics_t* m) {
    uint8_t n = m->scroll_visible ? m->scroll_visible : 1;
    if (m->mono) return n;
    while (n > 1 && strip_cap_for(m, n) < MW_KB_MIN_KEY_PX) n--;
    return n;
}

// The strip shows exactly strip_visible() whole caps: its width is trimmed
// to n caps plus gaps, and scrolling snaps to a cap's left edge.
static lv_coord_t strip_cap_w(const mw_metrics_t* m) {
    lv_coord_t cw = strip_cap_for(m, strip_visible(m));
    if (cw < 8) cw = 8;
    if (!m->mono && cw < MW_KB_MIN_KEY_PX) cw = MW_KB_MIN_KEY_PX;
    return cw;
}

void mw_kb_scroll_build(mw_kb_state_t* st) {
    const mw_metrics_t* m = mw_metrics();

    mw_kb_fill_cells(st);

    const lv_coord_t cap_w  = strip_cap_w(m);
    const lv_coord_t cap_h  = m->compact ? m->bar_h
                                         : (lv_coord_t)(m->bar_h * 3 / 2);
    const uint8_t    vis    = strip_visible(m);

    lv_obj_t* row = lv_obj_create(st->page.body);
    lv_obj_remove_style_all(row);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, cap_h);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(row, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    MW_OBJ_CLEAR_FLAG(row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* left = MW_BTN_CREATE(row);
    lv_obj_remove_style_all(left);
    lv_obj_add_style(left, mw_style_key(), LV_PART_MAIN);
    lv_obj_add_style(left, mw_style_focus(), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_add_style(left, mw_style_pressed(), LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_size(left, m->row_h, cap_h);
    lv_obj_add_flag(left, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_t* ll = lv_label_create(left);
    lv_label_set_text(ll, LV_SYMBOL_LEFT);
    lv_obj_center(ll);
    lv_obj_add_event_cb(left, scroll_left_cb, LV_EVENT_CLICKED, st);
    mw_ui_focus_add(&st->page, left);

    st->strip = lv_obj_create(row);
    lv_obj_remove_style_all(st->strip);
    lv_obj_set_size(st->strip, (lv_coord_t)(vis * cap_w + (vis - 1) * strip_gap(m)), cap_h);
    lv_obj_set_flex_flow(st->strip, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(st->strip, strip_gap(m), LV_PART_MAIN);
    lv_obj_add_flag(st->strip, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(st->strip, LV_DIR_HOR);
    lv_obj_set_scroll_snap_x(st->strip, LV_SCROLL_SNAP_START);
    lv_obj_set_scrollbar_mode(st->strip, LV_SCROLLBAR_MODE_OFF);

    for (int i = 0; i < MW_KB_LETTERS; i++) {
        mw_kb_make_key(st, st->strip, i, cap_w, cap_h);
    }

    lv_obj_t* right = MW_BTN_CREATE(row);
    lv_obj_remove_style_all(right);
    lv_obj_add_style(right, mw_style_key(), LV_PART_MAIN);
    lv_obj_add_style(right, mw_style_focus(), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_add_style(right, mw_style_pressed(), LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_size(right, m->row_h, cap_h);
    lv_obj_add_flag(right, LV_OBJ_FLAG_EVENT_BUBBLE);
    lv_obj_t* rl = lv_label_create(right);
    lv_label_set_text(rl, LV_SYMBOL_RIGHT);
    lv_obj_center(rl);
    lv_obj_add_event_cb(right, scroll_right_cb, LV_EVENT_CLICKED, st);
    mw_ui_focus_add(&st->page, right);

    lv_obj_t* sp = lv_obj_create(st->page.body);
    lv_obj_remove_style_all(sp);
    lv_obj_set_width(sp, lv_pct(100));
    lv_obj_set_height(sp, m->row_h);
    lv_obj_set_flex_flow(sp, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(sp, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_align(sp, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    MW_OBJ_CLEAR_FLAG(sp, LV_OBJ_FLAG_SCROLLABLE);
    st->keys_cont = sp;

    const lv_coord_t sw = (lv_coord_t)((m->w - 2 * m->pad - 3 * m->gap) / 4);
    for (int i = SCROLL_SPECIAL_FIRST; i < MW_KB_GRID_CELLS; i++) {
        mw_kb_make_key(st, sp, i, sw, m->row_h);
    }

    st->area    = MW_KB_AREA_KEYS;
    st->cur_row = 0;
    st->cur_col = 0;
}

// ---------------------------------------------------------------------------
static void scroll_focus_current(mw_kb_state_t* st) {
    switch (st->area) {
    case MW_KB_AREA_HEADER: {
        lv_obj_t* h = (st->head_col == 1 && st->btn_ok) ? st->btn_ok : st->btn_back;
        if (h) mw_kb_focus(st, h);
        break;
    }
    case MW_KB_AREA_CAND:
        if (st->cur_row >= 0 && st->cur_row < st->cand_slots) {
            mw_kb_focus(st, st->cand_btn[st->cur_row]);
        }
        break;
    case MW_KB_AREA_FOOTER: {
        const int cell = SCROLL_SPECIAL_FIRST + st->cur_row;
        if (cell >= SCROLL_SPECIAL_FIRST && cell < MW_KB_GRID_CELLS) {
            mw_kb_focus(st, st->key_btn[cell]);
        }
        break;
    }
    case MW_KB_AREA_KEYS:
    default:
        if (st->cur_col >= 0 && st->cur_col < MW_KB_LETTERS &&
            st->key_btn[st->cur_col]) {
            mw_kb_focus(st, st->key_btn[st->cur_col]);
            lv_obj_scroll_to_view(st->key_btn[st->cur_col], LV_ANIM_ON);
        }
        break;
    }
}

static void scroll_step(mw_kb_state_t* st, int dir) {
    int i = st->cur_col;
    for (int guard = 0; guard < MW_KB_LETTERS; guard++) {
        i += dir;
        if (i < 0) i = MW_KB_LETTERS - 1;
        if (i >= MW_KB_LETTERS) i = 0;
        if (mw_kb_letter_live(st, st->key_ch[i])) break;
    }
    st->cur_col = i;
    st->area    = MW_KB_AREA_KEYS;
    scroll_focus_current(st);
}

static void scroll_left_cb(lv_event_t* e) {
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    if (!st) return;
    mw_kb_touch_activity(st);
    scroll_step(st, -1);
}

static void scroll_right_cb(lv_event_t* e) {
    mw_kb_state_t* st = (mw_kb_state_t*)lv_event_get_user_data(e);
    if (!st) return;
    mw_kb_touch_activity(st);
    scroll_step(st, 1);
}

void mw_kb_scroll_update(mw_kb_state_t* st) {
    mw_kb_paint_cells(st);

    if (st->cur_col >= 0 && st->cur_col < MW_KB_LETTERS &&
        !mw_kb_letter_live(st, st->key_ch[st->cur_col])) {
        scroll_step(st, 1);
    } else {
        // Keep the LVGL focus in sync with the logical state: at startup the
        // group's first object (the header [Back] button) is auto-focused,
        // but the keyboard starts on the first letter.
        scroll_focus_current(st);
    }
}

// ---------------------------------------------------------------------------
// Buttons (keyboard_nav.h). The handler below works in terms of the old
// direction switch; the nav model decides when a button acts at all.
// ---------------------------------------------------------------------------
// Four-button boards: [Back] - candidates - letters - specials, as one list.
static int scroll_head_n(const mw_kb_state_t* st) {
    return (st->btn_back ? 1 : 0) + (st->btn_ok ? 1 : 0);
}

static int scroll_lin_count(const mw_kb_state_t* st) {
    return scroll_head_n(st) + st->cand_n + MW_KB_LETTERS +
           (MW_KB_GRID_CELLS - SCROLL_SPECIAL_FIRST);
}

static int scroll_lin_index(const mw_kb_state_t* st) {
    const int head = scroll_head_n(st);
    switch (st->area) {
    case MW_KB_AREA_HEADER: return (st->head_col == 1 && st->btn_ok && st->btn_back) ? 1 : 0;
    case MW_KB_AREA_CAND:   return head + st->cur_row;
    case MW_KB_AREA_FOOTER: return head + st->cand_n + MW_KB_LETTERS + st->cur_row;
    default:                return head + st->cand_n + st->cur_col;
    }
}

static bool scroll_lin_live(int i, void* ctx) {
    const mw_kb_state_t* st = (const mw_kb_state_t*)ctx;
    const int head = scroll_head_n(st);
    if (i < head) return true;
    i -= head;
    if (i < st->cand_n) return true;
    i -= st->cand_n;
    if (i < MW_KB_LETTERS) return mw_kb_letter_live(st, st->key_ch[i]);
    return true;
}

static void scroll_lin_set(mw_kb_state_t* st, int i) {
    const int head = scroll_head_n(st);
    if (i < head) {
        st->area = MW_KB_AREA_HEADER;
        st->head_col = (st->btn_back && i == 0) ? 0 : 1;
        return;
    }
    i -= head;
    if (i < st->cand_n) { st->area = MW_KB_AREA_CAND; st->cur_row = i; return; }
    i -= st->cand_n;
    if (i < MW_KB_LETTERS) { st->area = MW_KB_AREA_KEYS; st->cur_col = i; return; }
    st->area = MW_KB_AREA_FOOTER;
    st->cur_row = i - MW_KB_LETTERS;
}

bool mw_kb_scroll_button(mw_kb_state_t* st, mw_button_t b, uint32_t hold_ms,
                         bool released) {
    const mw_kn_out_t o = mw_kn_event(&st->nav, b, hold_ms, released, mw_millis());
    switch (o.act) {
    case MW_KN_NONE:
        return true;
    case MW_KN_FINISH:
        mw_kb_touch_activity(st);
        mw_kb_finish(st, MW_KB_R_OK);
        return true;
    case MW_KN_BACKSPACE:
        mw_kb_touch_activity(st);
        mw_kb_backspace(st);
        return true;
    case MW_KN_CANCEL:
        mw_kb_finish(st, st->ctx.allow_back ? MW_KB_R_BACK : MW_KB_R_CANCEL);
        return true;
    case MW_KN_LAYOUT: {
        mw_kb_touch_activity(st);
        if (o.undo_move) {
            st->area = st->prev_area; st->cur_row = st->prev_row; st->cur_col = st->prev_col;
        }
        const int lc = mw_kb_layer_cell(st);
        if (lc >= 0) mw_kb_cell_activate(st, lc);
        scroll_focus_current(st);
        return true;
    }
    case MW_KN_MOVE:
        st->prev_area = st->area; st->prev_row = st->cur_row; st->prev_col = st->cur_col;
        if (st->linear) {
            mw_kb_touch_activity(st);
            const int d = (o.dir == MW_BTN_UP || o.dir == MW_BTN_LEFT) ? -1 : 1;
            scroll_lin_set(st, mw_kn_linear_step(scroll_lin_count(st), scroll_lin_index(st),
                                                 d, scroll_lin_live, st));
            scroll_focus_current(st);
            return true;
        }
        b = o.dir;
        break;
    case MW_KN_ACTIVATE:
        b = MW_BTN_SELECT;
        break;
    default:
        return true;
    }

    mw_kb_touch_activity(st);

    switch (b) {
    case MW_BTN_LEFT:
        if (st->area == MW_KB_AREA_HEADER) {
            if (st->btn_back) st->head_col = 0;
            scroll_focus_current(st);
            break;
        }
        if (st->area == MW_KB_AREA_FOOTER) {
            if (st->cur_row > 0) st->cur_row--;
            scroll_focus_current(st);
        } else {
            scroll_step(st, -1);
        }
        break;

    case MW_BTN_RIGHT:
        if (st->area == MW_KB_AREA_HEADER) {
            if (st->btn_ok) st->head_col = 1;
            scroll_focus_current(st);
            break;
        }
        if (st->area == MW_KB_AREA_FOOTER) {
            if (st->cur_row < MW_KB_GRID_CELLS - SCROLL_SPECIAL_FIRST - 1) st->cur_row++;
            scroll_focus_current(st);
        } else {
            scroll_step(st, 1);
        }
        break;

    case MW_BTN_UP:
        if (st->area == MW_KB_AREA_HEADER) break;      // already there
        if (st->area == MW_KB_AREA_FOOTER) {
            st->area = MW_KB_AREA_KEYS;
        } else if (st->area == MW_KB_AREA_KEYS) {
            if (st->cand_n > 0) {
                st->area    = MW_KB_AREA_CAND;
                st->cur_row = st->cand_n - 1;
            } else if (st->btn_back) {
                st->area = MW_KB_AREA_HEADER;
                st->head_col = 0;
            }
        } else if (st->cur_row > 0) {
            st->cur_row--;
        } else if (st->btn_back) {
            st->area = MW_KB_AREA_HEADER;
            st->head_col = 0;
        }
        scroll_focus_current(st);
        break;

    case MW_BTN_DOWN:
        if (st->area == MW_KB_AREA_HEADER) {
            st->area    = MW_KB_AREA_KEYS;
            st->cur_row = 0;
            scroll_focus_current(st);
            break;
        }
        if (st->area == MW_KB_AREA_CAND) {
            if (st->cur_row < st->cand_n - 1) st->cur_row++;
            else st->area = MW_KB_AREA_KEYS;
        } else if (st->area == MW_KB_AREA_KEYS) {
            st->area    = MW_KB_AREA_FOOTER;
            st->cur_row = 0;
        }
        scroll_focus_current(st);
        break;

    case MW_BTN_SELECT:
        if (st->area == MW_KB_AREA_HEADER) {
            if (st->head_col == 1 && st->btn_ok) mw_kb_ok(st);
            else mw_kb_finish(st, st->ctx.allow_back ? MW_KB_R_BACK : MW_KB_R_CANCEL);
            return true;
        }
        if (st->area == MW_KB_AREA_CAND) {
            mw_kb_accept_candidate(st, st->cur_row);
        } else if (st->area == MW_KB_AREA_FOOTER) {
            mw_kb_cell_activate(st, SCROLL_SPECIAL_FIRST + st->cur_row);
        } else {
            mw_kb_cell_activate(st, st->cur_col);
        }
        return true;

    default:
        break;
    }
    return true;
}