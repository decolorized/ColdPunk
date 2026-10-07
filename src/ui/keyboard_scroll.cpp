// ---------------------------------------------------------------------------
//  On-screen keyboard: type 2 "scroll keyboard" (TZ 5.4).
//
//  The model, the candidate logic and the cell semantics live in
//  keyboard_full.cpp and are shared verbatim.
//
//  Button semantics (TZ 5.6):
//    * Back, hold       - backspace with auto-repeat;
//    * arrows, hold     - one step now, repeat after the delay;
//    * SELECT, short    - act on the focused cell on RELEASE (letter,
//                         candidate, special, or [Back] in the header);
//    * SELECT, hold     - the moment hold_ms reaches MW_BACK_LONG_MS, finish
//                         the input (MW_KB_R_OK) right away. Nothing is typed
//                         on the press edge, so a long press cannot emit a
//                         spurious character before finishing.
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
    case MW_KB_AREA_HEADER:
        if (st->btn_back) mw_kb_focus(st, st->btn_back);
        break;
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
// Arrow / Back auto-repeat, same shape as in keyboard_full.cpp.
// ---------------------------------------------------------------------------
static bool repeat_should_fire(mw_kb_state_t* st, mw_button_t b,
                               uint32_t hold_ms, bool released) {
    if (released) {
        if (st->repeat_btn == b) st->repeat_btn = (mw_button_t)0;
        return false;
    }
    if (hold_ms == 0) {
        st->repeat_btn     = b;
        st->repeat_next_ms = mw_millis() + MW_ARROW_REPEAT_DELAY_MS;
        return true;
    }
    if (st->repeat_btn != b) return false;
    const uint32_t now = mw_millis();
    if ((int32_t)(now - st->repeat_next_ms) < 0) return false;
    st->repeat_next_ms = now + MW_ARROW_REPEAT_INTERVAL_MS;
    return true;
}

bool mw_kb_scroll_button(mw_kb_state_t* st, mw_button_t b, uint32_t hold_ms,
                         bool released) {
    if (b == MW_BTN_BACK) {
        if (repeat_should_fire(st, b, hold_ms, released)) {
            mw_kb_backspace(st);
        }
        return true;
    }

    const bool is_arrow = (b == MW_BTN_LEFT || b == MW_BTN_RIGHT ||
                           b == MW_BTN_UP   || b == MW_BTN_DOWN);

    if (is_arrow) {
        if (!repeat_should_fire(st, b, hold_ms, released)) return true;
    } else if (b == MW_BTN_SELECT) {
        // SELECT semantics:
        //   * press edge:  latch the button, do NOT act yet;
        //   * hold:        the moment hold_ms >= MW_BACK_LONG_MS, finish the
        //                  input right away and mark the hold as consumed;
        //   * release:     if the hold already fired, do nothing; otherwise
        //                  the short action runs in the switch below.
        //
        // Nothing is typed on the press edge, so a long press cannot emit a
        // spurious character before finishing.
        if (released) {
            const bool was_select = (st->repeat_btn == MW_BTN_SELECT);
            st->repeat_btn = (mw_button_t)0;
            if (!was_select) return true;
            if (st->select_hold_fired) {
                st->select_hold_fired = false;
                return true;                 // long press already handled
            }
            // short SELECT: fall through to the switch below
        } else {
            if (hold_ms == 0) {
                st->repeat_btn        = MW_BTN_SELECT;
                st->select_hold_fired = false;
                return true;                 // do not type yet
            }
            if (st->repeat_btn != MW_BTN_SELECT) return true;
            if (!st->select_hold_fired && hold_ms >= MW_BACK_LONG_MS) {
                st->select_hold_fired = true;
                mw_kb_finish(st, MW_KB_R_OK);
            }
            return true;
        }
    } else {
        if (released || hold_ms != 0) return true;
    }

    mw_kb_touch_activity(st);

    switch (b) {
    case MW_BTN_LEFT:
        if (st->area == MW_KB_AREA_HEADER) break;
        if (st->area == MW_KB_AREA_FOOTER) {
            if (st->cur_row > 0) st->cur_row--;
            scroll_focus_current(st);
        } else {
            scroll_step(st, -1);
        }
        break;

    case MW_BTN_RIGHT:
        if (st->area == MW_KB_AREA_HEADER) break;
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
            }
        } else if (st->cur_row > 0) {
            st->cur_row--;
        } else if (st->btn_back) {
            st->area = MW_KB_AREA_HEADER;
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
            mw_kb_finish(st, st->ctx.allow_back ? MW_KB_R_BACK : MW_KB_R_CANCEL);
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