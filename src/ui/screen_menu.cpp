// ---------------------------------------------------------------------------
//  Generic menu page (task 3): the main menu, the wallet list and the wallet
//  menu are all this one page, run from the crypto task.
//
//      ┌──────────────────────────────┐
//      │                 SD USB  85%  │  status bar
//      │  borya                       │  title
//      │  with passphrase · ready     │  subtitle (dim)
//      │  ┌────────────────────────┐  │
//      │  │ ⌂ Address              │  │
//      │  │ ⌂ Address (QR)         │  │
//      │  │ ...                    │  │
//      │  └────────────────────────┘  │
//      │          [ Back ]            │
//      └──────────────────────────────┘
//
//  Menu lists are NOT scrollable containers of their own when they fit: a
//  tap that the touch driver reports with a few pixels of jitter would
//  otherwise start a scroll and LVGL would swallow the CLICKED event - one of
//  the reasons a row could "click but do nothing" (task 3 item 0). The page
//  also raises the scroll threshold of the pointer for the same reason
//  (lvgl_port.cpp).
//
//  `wake`: while the wallet menu is open the device must react to files and
//  requests from the PC. The USB link bumps mw_ui_wake(); a timer on this
//  page notices it and returns MW_MENU_WAKE so the crypto task can handle the
//  event and then show the menu again.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../hal/log.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    mw_page_t     page;
    const mw_menu_t* m;
    lv_timer_t*   timer;
    bool          done;
} menu_ctx_t;

static menu_ctx_t s_menu;

static void menu_finish(int32_t r) {
    if (s_menu.done) return;
    s_menu.done = true;
    if (s_menu.timer) {
        MW_TIMER_DEL(s_menu.timer);
        s_menu.timer = NULL;
    }
    mw_ui_page_destroy(&s_menu.page);
    mw_ui_modal_done(r);
}

static void row_cb(lv_event_t* e) {
    const int idx = (int)(intptr_t)lv_event_get_user_data(e);
    MW_LOGD("menu", "row %d clicked", idx);
    menu_finish(idx);
}

static void back_cb(lv_event_t* e)  { MW_UNUSED(e); menu_finish(MW_MENU_BACK); }
static void escape_cb(void* user)   { MW_UNUSED(user); menu_finish(MW_MENU_BACK); }
static void cancel_now(void)        { menu_finish(MW_MENU_BACK); }

static void wake_timer_cb(lv_timer_t* t) {
    MW_UNUSED(t);
    if (!s_menu.m || s_menu.done) return;
    if (s_menu.m->wake && mw_ui_wake_seq() != s_menu.m->wake_seq) {
        MW_LOGD("menu", "wake");
        menu_finish(MW_MENU_WAKE);
    }
}

static void menu_build(void* arg) {
    menu_ctx_t* c = (menu_ctx_t*)arg;
    const mw_menu_t* m = c->m;
    const mw_metrics_t* mt = mw_metrics();

    c->done = false;
    mw_ui_page_create(&c->page, m->title ? m->title : "", m->with_status);
    if (m->back) mw_ui_page_set_escape(&c->page, escape_cb, c);
    mw_ui_modal_set_cancel(cancel_now);

    if (m->subtitle && m->subtitle[0]) {
        mw_ui_label(c->page.body, m->subtitle, mw_style_dim());
    }

    lv_obj_t* list = mw_ui_list(c->page.body);
    lv_obj_t* focus_row = NULL;
    for (int i = 0; i < m->count && i < MW_MENU_MAX; i++) {
        lv_obj_t* row = mw_ui_list_row(list, m->icons ? m->icons[i] : NULL,
                                       m->items[i], row_cb, (void*)(intptr_t)i);
        if (!row) continue;
        // A menu row is a button, not a scroll handle.
        MW_OBJ_CLEAR_FLAG(row, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        if (m->danger && m->danger[i]) {
            lv_obj_set_style_text_color(row, mw_palette()->danger, LV_PART_MAIN);
        }
        mw_ui_focus_add(&c->page, row);
        if (i == m->initial) focus_row = row;
    }

    if (m->footnote && m->footnote[0]) {
        lv_obj_t* l = mw_ui_label(c->page.body, m->footnote, mw_style_dim());
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    }

    if (m->back) {
        lv_obj_t* f = mw_ui_page_footer(&c->page);
        lv_obj_t* b = mw_ui_button(f, m->back_label ? m->back_label : T(STR_BACK),
                                   back_cb, NULL);
        lv_obj_set_flex_grow(b, 1);
        mw_ui_focus_add(&c->page, b);
    }

    // Scroll only when the rows really do not fit. Decided after the
    // footnote and the footer exist, since both take height from the list.
    // When the list scrolls, button boards bring the focused row into view.
    lv_obj_update_layout(c->page.scr);
    if (lv_obj_get_scroll_bottom(list) <= 0 && lv_obj_get_scroll_top(list) <= 0) {
        MW_OBJ_CLEAR_FLAG(list, LV_OBJ_FLAG_SCROLLABLE);
    } else if (mt->buttons) {
        const uint32_t n = lv_obj_get_child_count(list);
        for (uint32_t i = 0; i < n; i++) {
            lv_obj_add_flag(lv_obj_get_child(list, (int32_t)i), LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        }
    }
    if (focus_row) lv_group_focus_obj(focus_row);

    c->timer = m->wake ? lv_timer_create(wake_timer_cb, 120, NULL) : NULL;
}

int mw_ui_menu_run(const mw_menu_t* m) {
    if (!m || !m->items || m->count <= 0) return MW_MENU_BACK;
    memset(&s_menu, 0, sizeof(s_menu));
    s_menu.m = m;
    const int32_t r = mw_ui_modal_call(menu_build, &s_menu);
    s_menu.m = NULL;
    if (r == MW_MENU_WAKE) return MW_MENU_WAKE;
    if (r < 0 || r >= m->count) return MW_MENU_BACK;
    return (int)r;
}
