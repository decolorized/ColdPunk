// ---------------------------------------------------------------------------
//  Shared screen furniture: the page/overlay frame, the status bar, the small
//  widget helpers and the three blocking helpers of ui.h (confirm / message /
//  progress) plus the generic chooser and the full-text viewer.
//
//  Everything named *_build / *_cb here runs on the LVGL task only. The
//  public helpers at the bottom marshal onto it (see lvgl_port.cpp).
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../hal/log.h"

#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// One page at a time on top of the root screen (TZ memory rule).
// ---------------------------------------------------------------------------
static mw_page_t* s_active_page = NULL;

// ---------------------------------------------------------------------------
// Modal cancellation (autolock, task 3) and the wake signal.
//
// Every modal builder registers how to close itself with a "cancelled"
// result; mw_ui_modal_done() drops the registration again. The autolock
// (lvgl_port.cpp) then closes whatever the crypto task is waiting on, without
// knowing what it is. Pages that register nothing are still closed through
// mw_ui_page_cancel_active().
// ---------------------------------------------------------------------------
static mw_ui_cancel_fn s_cancel_fn = NULL;
static volatile uint32_t s_wake_seq = 0;

void mw_ui_modal_set_cancel(mw_ui_cancel_fn fn) { s_cancel_fn = fn; }
void mw_ui_modal_clear_cancel(void)            { s_cancel_fn = NULL; }

void mw_ui_cancel_modal(void) {
    mw_ui_cancel_fn fn = s_cancel_fn;
    s_cancel_fn = NULL;
    MW_LOGD("ui", "cancel_modal fn=%p page=%p", (void*)fn, (void*)s_active_page);
    if (fn) { fn(); return; }
    mw_ui_page_cancel_active();
}

void     mw_ui_wake(void)     { s_wake_seq++; }
uint32_t mw_ui_wake_seq(void) { return s_wake_seq; }

// ---------------------------------------------------------------------------
// Per-screen focus memory.
// ---------------------------------------------------------------------------
static int s_focus_slot[MW_FOCUS_COUNT] = { 0 };

void mw_ui_focus_remember(mw_focus_slot_t slot, int index) {
    if ((unsigned)slot >= MW_FOCUS_COUNT) return;
    if (index < 0) index = 0;
    MW_LOGD("ui", "focus_remember slot=%d idx=%d", (int)slot, index);
    s_focus_slot[slot] = index;
}

int mw_ui_focus_restore(mw_focus_slot_t slot) {
    if ((unsigned)slot >= MW_FOCUS_COUNT) return 0;
    return s_focus_slot[slot];
}

// ---------------------------------------------------------------------------
// Status bar (TZ 4.2)
// ---------------------------------------------------------------------------
#define MW_STATUS_SLOTS 4
static lv_obj_t* s_status_slots[MW_STATUS_SLOTS];

static void status_del_cb(lv_event_t* e) {
    lv_obj_t* obj = MW_EVT_OBJ(e);
    for (int i = 0; i < MW_STATUS_SLOTS; i++) {
        if (s_status_slots[i] == obj) s_status_slots[i] = NULL;
    }
}

static const char* battery_symbol(int pct) {
    if (pct < 0)  return LV_SYMBOL_POWER;
    if (pct > 87) return LV_SYMBOL_BATTERY_FULL;
    if (pct > 62) return LV_SYMBOL_BATTERY_3;
    if (pct > 37) return LV_SYMBOL_BATTERY_2;
    if (pct > 12) return LV_SYMBOL_BATTERY_1;
    return LV_SYMBOL_BATTERY_EMPTY;
}

static void status_paint(lv_obj_t* bar) {
    int  batt = -1;
    bool sd = false, usb = false;
    mw_ui_status_values(&batt, &sd, &usb);

    lv_obj_t* lbl = lv_obj_get_child(bar, 0);
    if (!lbl) return;

    char txt[64];
    if (mw_metrics()->compact) {
        snprintf(txt, sizeof(txt), "%s%s%s",
                 sd  ? LV_SYMBOL_SD_CARD : "",
                 usb ? LV_SYMBOL_USB     : "",
                 battery_symbol(batt));
    } else if (batt >= 0) {
        snprintf(txt, sizeof(txt), "%s %s %s %d%%",
                 sd  ? LV_SYMBOL_SD_CARD : " ",
                 usb ? LV_SYMBOL_USB     : " ",
                 battery_symbol(batt), batt);
    } else {
        snprintf(txt, sizeof(txt), "%s %s %s",
                 sd  ? LV_SYMBOL_SD_CARD : " ",
                 usb ? LV_SYMBOL_USB     : " ",
                 battery_symbol(batt));
    }
    lv_label_set_text(lbl, txt);
}

static lv_obj_t* status_widget(lv_obj_t* parent, bool inline_row) {
    const mw_metrics_t* m = mw_metrics();

    lv_obj_t* bar = lv_obj_create(parent);
    lv_obj_remove_style_all(bar);
    if (inline_row) {
        lv_obj_set_size(bar, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    } else {
        lv_obj_set_width(bar, lv_pct(100));
        lv_obj_set_height(bar, m->status_h);
        lv_obj_set_style_bg_color(bar, mw_palette()->surface, LV_PART_MAIN);
        lv_obj_set_style_bg_opa(bar, LV_OPA_COVER, LV_PART_MAIN);
        lv_obj_set_style_pad_left(bar, m->pad, LV_PART_MAIN);
        lv_obj_set_style_pad_right(bar, m->pad, LV_PART_MAIN);
    }
    MW_OBJ_CLEAR_FLAG(bar, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* lbl = lv_label_create(bar);
    lv_obj_add_style(lbl, mw_style_dim(), LV_PART_MAIN);
    if (!inline_row) lv_obj_align(lbl, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_label_set_text(lbl, "");

    for (int i = 0; i < MW_STATUS_SLOTS; i++) {
        if (!s_status_slots[i]) { s_status_slots[i] = bar; break; }
    }
    lv_obj_add_event_cb(bar, status_del_cb, LV_EVENT_DELETE, NULL);

    status_paint(bar);
    return bar;
}

lv_obj_t* mw_ui_status_bar(lv_obj_t* parent) {
    return status_widget(parent, false);
}

void mw_ui_status_apply(void) {
    for (int i = 0; i < MW_STATUS_SLOTS; i++) {
        if (s_status_slots[i]) status_paint(s_status_slots[i]);
    }
}

// ---------------------------------------------------------------------------
// Page / overlay frame
// ---------------------------------------------------------------------------
static void page_key_cb(lv_event_t* e) {
    mw_page_t* p = (mw_page_t*)lv_event_get_user_data(e);
    if (!p || !p->on_escape) return;
    uint32_t key = lv_event_get_key(e);
    if (key == LV_KEY_ESC) p->on_escape(p->escape_user);
}

static void page_body_init(mw_page_t* p, const char* title, bool with_status) {
    const mw_metrics_t* m = mw_metrics();

    lv_obj_remove_style_all(p->scr);
    lv_obj_add_style(p->scr, mw_style_page(), LV_PART_MAIN);
    lv_obj_set_size(p->scr, lv_pct(100), lv_pct(100));
    lv_obj_set_style_pad_all(p->scr, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_row(p->scr, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_flow(p->scr, LV_FLEX_FLOW_COLUMN);
    MW_OBJ_CLEAR_FLAG(p->scr, LV_OBJ_FLAG_SCROLLABLE);

    const bool inline_status = with_status && m->compact;

    if (with_status && !m->compact && m->status_h > 0) {
        p->status = mw_ui_status_bar(p->scr);
    }

    if (inline_status) {
        lv_obj_t* row = lv_obj_create(p->scr);
        lv_obj_remove_style_all(row);
        lv_obj_set_width(row, lv_pct(100));
        lv_obj_set_height(row, LV_SIZE_CONTENT);
        lv_obj_set_style_pad_left(row, m->pad, LV_PART_MAIN);
        lv_obj_set_style_pad_right(row, m->pad, LV_PART_MAIN);
        lv_obj_set_style_pad_column(row, m->gap, LV_PART_MAIN);
        lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        MW_OBJ_CLEAR_FLAG(row, LV_OBJ_FLAG_SCROLLABLE);

        p->title = lv_label_create(row);
        lv_obj_add_style(p->title, mw_style_title(), LV_PART_MAIN);
        lv_label_set_long_mode(p->title, LV_LABEL_LONG_DOT);
        lv_obj_set_flex_grow(p->title, 1);
        lv_label_set_text(p->title, (title && title[0]) ? title : "");

        p->status = status_widget(row, true);
    } else if (title && title[0]) {
        p->title = lv_label_create(p->scr);
        lv_obj_add_style(p->title, mw_style_title(), LV_PART_MAIN);
        lv_label_set_long_mode(p->title, LV_LABEL_LONG_DOT);
        lv_obj_set_width(p->title, lv_pct(100));
        // One line: a long title ends in '...' instead of wrapping.
        lv_obj_set_height(p->title, (lv_coord_t)lv_font_get_line_height(m->font_title));
        lv_obj_set_style_pad_left(p->title, m->pad, LV_PART_MAIN);
        lv_obj_set_style_pad_right(p->title, m->pad, LV_PART_MAIN);
        lv_label_set_text(p->title, title);
    }

    p->body = lv_obj_create(p->scr);
    lv_obj_remove_style_all(p->body);
    lv_obj_set_width(p->body, lv_pct(100));
    lv_obj_set_flex_grow(p->body, 1);
    lv_obj_set_style_min_height(p->body, 16, LV_PART_MAIN);
    lv_obj_set_style_pad_all(p->body, m->pad, LV_PART_MAIN);
    lv_obj_set_style_pad_row(p->body, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_flow(p->body, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_clip_corner(p->body, true, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(p->body, LV_OBJ_FLAG_SCROLLABLE);

    p->prev_group = mw_ui_group_current();
    p->group      = lv_group_create();
    mw_ui_group_activate(p->group);
}

void mw_ui_page_create(mw_page_t* p, const char* title, bool with_status) {
    if (!p) return;
    MW_LOGD("page", "create p=%p title=%s active=%p",
           (void*)p, title ? title : "(null)", (void*)s_active_page);
    if (s_active_page) mw_ui_page_destroy(s_active_page);

    memset(p, 0, sizeof(*p));
    p->prev    = MW_SCR_ACT();
    p->scr     = lv_obj_create(NULL);
    p->overlay = false;
    page_body_init(p, title, with_status);
    MW_LOGD("page", "create: scr=%p prev=%p group=%p prev_group=%p",
           (void*)p->scr, (void*)p->prev, (void*)p->group, (void*)p->prev_group);
    MW_SCR_LOAD(p->scr);
    s_active_page = p;
    MW_LOGD("page", "create done");
}

// ---------------------------------------------------------------------------
// Overlay: a full screen of its own, NOT a child of the active screen.
//
// The previous revision created the overlay as a child of MW_SCR_ACT(). That
// makes the overlay inherit the parent's flex layout and padding, and on a
// 240x240 panel those few pixels are enough to push the footer (and its
// buttons) off the visible area - the user sees only the text and has to
// press the buttons blindly.
//
// The overlay is now a standalone screen loaded with MW_SCR_LOAD, exactly
// like a page. prev keeps the screen to restore on destroy.
// ---------------------------------------------------------------------------
void mw_ui_overlay_create(mw_page_t* p, const char* title) {
    if (!p) return;
    MW_LOGD("page", "overlay_create p=%p title=%s",
           (void*)p, title ? title : "(null)");
    memset(p, 0, sizeof(*p));
    p->prev    = MW_SCR_ACT();
    p->scr     = lv_obj_create(NULL);
    p->overlay = true;
    page_body_init(p, title, false);
    MW_SCR_LOAD(p->scr);
    MW_LOGD("page", "overlay_create done scr=%p group=%p prev=%p",
           (void*)p->scr, (void*)p->group, (void*)p->prev);
}

void mw_ui_page_destroy(mw_page_t* p) {
    if (!p || !p->scr) return;
    MW_LOGD("page", "destroy p=%p scr=%p group=%p prev_group=%p overlay=%d",
           (void*)p, (void*)p->scr, (void*)p->group,
           (void*)p->prev_group, (int)p->overlay);

    lv_group_t* restore = p->prev_group;
    lv_obj_t*   scr     = p->scr;
    lv_obj_t*   prev    = p->prev;
    const bool  overlay = p->overlay;

    p->scr = p->body = p->title = p->status = p->footer = NULL;
    p->on_escape = NULL;
    if (s_active_page == p) s_active_page = NULL;

    if (mw_ui_group_current() == p->group) {
        mw_ui_group_activate(restore);
    }
    if (p->group) {
        // Empty the group before deleting it: LVGL 9's lv_group_delete walks
        // the object list and may fire DEFOCUSED on objects whose user_data
        // has already been reset by the page_destroy path. Removing them
        // first keeps that walk harmless.
        uint32_t n = lv_group_get_obj_count(p->group);
        while (n--) {
            lv_obj_t* o = lv_group_get_obj_by_index(p->group, 0);
            if (o) lv_group_remove_obj(o);
            else break;
        }
        MW_GROUP_DEL(p->group);
        p->group = NULL;
    }

    // Hide the page BEFORE switching away: otherwise LVGL can render it and
    // the target screen in the same frame, which shows up as a flicker.
    lv_obj_add_flag(scr, LV_OBJ_FLAG_HIDDEN);
    MW_OBJ_CLEAR_FLAG(scr, LV_OBJ_FLAG_CLICKABLE);

    // Both pages and overlays are standalone screens now, so both restore
    // prev when destroyed.
    if (prev) {
        MW_SCR_LOAD(prev);
    }
    MW_UNUSED(overlay);

    MW_OBJ_DEL_ASYNC(scr);
}

void mw_ui_page_cancel_active(void) {
    if (!s_active_page) return;
    mw_ui_set_button_hook(NULL, NULL);
    mw_ui_page_destroy(s_active_page);
    mw_ui_modal_done(-1);
}

lv_obj_t* mw_ui_page_footer(mw_page_t* p) {
    if (!p || !p->scr) return NULL;
    if (p->footer) return p->footer;

    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* f = lv_obj_create(p->scr);
    lv_obj_remove_style_all(f);
    lv_obj_set_width(f, lv_pct(100));
    lv_obj_set_height(f, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_all(f, m->pad, LV_PART_MAIN);
    lv_obj_set_style_pad_column(f, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_flow(f, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(f, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    MW_OBJ_CLEAR_FLAG(f, LV_OBJ_FLAG_SCROLLABLE);
    p->footer = f;
    return f;
}

void mw_ui_focus_add(mw_page_t* p, lv_obj_t* obj) {
    if (!p || !p->group || !obj) return;
    lv_group_add_obj(p->group, obj);
    lv_obj_add_event_cb(obj, page_key_cb, LV_EVENT_KEY, p);
}

void mw_ui_page_set_escape(mw_page_t* p, void (*cb)(void*), void* user) {
    if (!p) return;
    p->on_escape   = cb;
    p->escape_user = user;
}

// ---------------------------------------------------------------------------
// Widget helpers
// ---------------------------------------------------------------------------
lv_obj_t* mw_ui_label(lv_obj_t* parent, const char* text, lv_style_t* style) {
    lv_obj_t* l = lv_label_create(parent);
    if (style) lv_obj_add_style(l, style, LV_PART_MAIN);
    lv_label_set_long_mode(l, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(l, lv_pct(100));
    lv_obj_set_height(l, LV_SIZE_CONTENT);
    lv_label_set_text(l, text ? text : "");
    return l;
}

lv_obj_t* mw_ui_button(lv_obj_t* parent, const char* text,
                       lv_event_cb_t cb, void* user) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* b = MW_BTN_CREATE(parent);
    mw_theme_button(b);
    lv_obj_set_height(b, m->btn_h);
    lv_obj_set_width(b, LV_SIZE_CONTENT);
    lv_obj_set_flex_grow(b, 1);
    lv_obj_add_flag(b, LV_OBJ_FLAG_EVENT_BUBBLE);

    // Narrow side padding so three footer buttons fit their captions on a
    // 240 px panel; a caption that still does not fit gets '...' on one line.
    lv_obj_set_style_pad_left(b, m->pad, LV_PART_MAIN);
    lv_obj_set_style_pad_right(b, m->pad, LV_PART_MAIN);

    lv_obj_t* l = lv_label_create(b);
    lv_label_set_long_mode(l, LV_LABEL_LONG_DOT);
    lv_label_set_text(l, text ? text : "");
    lv_obj_set_width(l, lv_pct(100));
    lv_obj_set_height(l, (lv_coord_t)lv_font_get_line_height(m->font_body));
    lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_center(l);

    if (cb) lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, user);
    return b;
}

lv_obj_t* mw_ui_list(lv_obj_t* parent) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* list = lv_list_create(parent);
    lv_obj_set_width(list, lv_pct(100));
    lv_obj_set_flex_grow(list, 1);
    lv_obj_set_style_bg_color(list, mw_palette()->bg, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(list, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_border_width(list, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(list, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_row(list, m->mono ? 0 : 2, LV_PART_MAIN);
    lv_obj_set_style_radius(list, 0, LV_PART_MAIN);
    return list;
}

lv_obj_t* mw_ui_list_row(lv_obj_t* list, const char* icon, const char* text,
                         lv_event_cb_t cb, void* user) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* row = MW_LIST_ADD_BTN(list, icon, text ? text : "");
    if (!row) return NULL;
    lv_obj_set_style_min_height(row, m->row_h, LV_PART_MAIN);
    lv_obj_set_style_bg_color(row, mw_palette()->surface, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(row, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_bg_color(row, mw_palette()->surface2,
                              LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_text_color(row, mw_palette()->text, LV_PART_MAIN);
    lv_obj_set_style_text_font(row, m->font_body, LV_PART_MAIN);
    lv_obj_set_style_radius(row, m->mono ? 0 : 4, LV_PART_MAIN);
    lv_obj_add_style(row, mw_style_focus(), LV_PART_MAIN | LV_STATE_FOCUSED);
    lv_obj_add_flag(row, LV_OBJ_FLAG_EVENT_BUBBLE);
    if (cb) lv_obj_add_event_cb(row, cb, LV_EVENT_CLICKED, user);
    return row;
}

lv_coord_t mw_ui_free_height(lv_obj_t* column) {
    // A probe is used instead of growing the real object: LVGL keeps a size
    // taken from flex_grow even after the grow is reset to 0.
    lv_obj_t* probe = lv_obj_create(column);
    lv_obj_remove_style_all(probe);
    lv_obj_set_size(probe, 1, 0);
    lv_obj_set_flex_grow(probe, 1);
    lv_obj_update_layout(lv_obj_get_screen(column));
    const lv_coord_t h = (lv_coord_t)lv_obj_get_height(probe);
    MW_OBJ_DEL(probe);
    return h;
}

lv_obj_t* mw_ui_bar(lv_obj_t* parent) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* bar = lv_bar_create(parent);
    lv_obj_set_width(bar, lv_pct(100));
    lv_obj_set_height(bar, m->compact ? 6 : 12);
    lv_bar_set_range(bar, 0, 1000);
    lv_bar_set_value(bar, 0, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(bar, mw_palette()->surface, LV_PART_MAIN);
    lv_obj_set_style_bg_color(bar, mw_palette()->accent, LV_PART_INDICATOR);
    lv_obj_set_style_bg_opa(bar, LV_OPA_COVER, LV_PART_INDICATOR);
    return bar;
}

// ===========================================================================
//  Blocking helpers of ui.h
// ===========================================================================

static int count_lines(const char* s) {
    if (!s) return 0;
    int n = 1;
    for (const char* p = s; *p; p++) if (*p == '\n') n++;
    return n;
}

static lv_obj_t* make_scroll_body(lv_obj_t* parent, const char* text) {
    // The box takes the space the parent has left for it, but never more:
    // a long text otherwise stretches the body, pushes the footer off the
    // panel, and the buttons become invisible. flex_grow + max_height 100%
    // is the combination that keeps the box bounded and scrollable.
    lv_obj_t* box = lv_obj_create(parent);
    lv_obj_remove_style_all(box);
    lv_obj_set_width(box, lv_pct(100));
    lv_obj_set_flex_grow(box, 1);
    lv_obj_set_style_max_height(box, lv_pct(100), LV_PART_MAIN);
    lv_obj_add_flag(box, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(box, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(box, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_set_style_pad_all(box, 0, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(box, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t* lbl = mw_ui_label(box, text, NULL);
    lv_obj_set_width(lbl, lv_pct(100));
    lv_obj_set_height(lbl, LV_SIZE_CONTENT);

    return box;
}

static void add_scroll_hint_into(lv_obj_t* box, const char* text) {
    const mw_metrics_t* m = mw_metrics();
    const int limit = m->compact ? 3 : 5;
    if (count_lines(text) <= limit) return;

    lv_obj_t* hint = mw_ui_label(box, LV_SYMBOL_DOWN "  " LV_SYMBOL_DOWN,
                                 mw_style_dim());
    lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_set_width(hint, lv_pct(100));
    lv_obj_set_height(hint, LV_SIZE_CONTENT);
}

// ---------------- confirm --------------------------------------------------
typedef struct {
    const char* title;
    const char* body;
    const char* ok;
    const char* cancel;
    mw_page_t   page;
    bool        done;
} confirm_ctx_t;

static confirm_ctx_t s_confirm;

static void confirm_finish(confirm_ctx_t* c, int32_t r) {
    if (c->done) return;
    c->done = true;
    mw_ui_page_destroy(&c->page);
    mw_ui_modal_done(r);
}
static void confirm_ok_cb(lv_event_t* e) {
    confirm_finish((confirm_ctx_t*)lv_event_get_user_data(e), 1);
}
static void confirm_cancel_cb(lv_event_t* e) {
    confirm_finish((confirm_ctx_t*)lv_event_get_user_data(e), 0);
}
static void confirm_escape(void* user) {
    confirm_finish((confirm_ctx_t*)user, 0);
}
static void confirm_cancel_now(void) { confirm_finish(&s_confirm, 0); }

static void confirm_build(void* arg) {
    confirm_ctx_t* c = (confirm_ctx_t*)arg;
    c->done = false;
    mw_ui_overlay_create(&c->page, c->title);
    mw_ui_page_set_escape(&c->page, confirm_escape, c);
    mw_ui_modal_set_cancel(confirm_cancel_now);

    lv_obj_t* box = make_scroll_body(c->page.body, c->body);
    add_scroll_hint_into(box, c->body);

    lv_obj_t* f  = mw_ui_page_footer(&c->page);
    if (!f) return;

    lv_obj_t* bc = mw_ui_button(f, c->cancel, confirm_cancel_cb, c);
    lv_obj_t* bo = mw_ui_button(f, c->ok, confirm_ok_cb, c);
    lv_obj_set_flex_grow(bc, 1);
    lv_obj_set_flex_grow(bo, 1);

    // Only the buttons take the focus. The scrolling text has no action,
    // and a focus on it makes the dialog look like it has no controls at
    // all on a small panel.
    mw_ui_focus_add(&c->page, bc);
    mw_ui_focus_add(&c->page, bo);
    lv_group_focus_obj(bc);

    MW_LOGD("confirm", "scr=%p h=%d body=%p h=%d box=%p h=%d footer=%p h=%d bc=%p bo=%p focus=%p",
           (void*)c->page.scr, (int)lv_obj_get_height(c->page.scr),
           (void*)c->page.body, (int)lv_obj_get_height(c->page.body),
           (void*)box, (int)lv_obj_get_height(box),
           (void*)f, (int)lv_obj_get_height(f),
           (void*)bc, (void*)bo,
           (void*)lv_group_get_focused(c->page.group));
}

bool mw_ui_confirm(const char* title, const char* body,
                   const char* ok, const char* cancel) {
    s_confirm.title  = title  ? title  : T(STR_CONFIRM);
    s_confirm.body   = body   ? body   : "";
    s_confirm.ok     = ok     ? ok     : T(STR_CONFIRM);
    s_confirm.cancel = cancel ? cancel : T(STR_CANCEL);
    s_confirm.done   = false;
    return mw_ui_modal_call(confirm_build, &s_confirm) == 1;
}

// ---------------- message --------------------------------------------------
typedef struct {
    const char* title;
    const char* body;
    uint32_t    timeout_ms;   // 0 = wait for the user
    mw_page_t   page;
    lv_timer_t* timer;
    bool        done;
} message_ctx_t;

static message_ctx_t s_message;

static void message_close(message_ctx_t* c) {
    if (c->done) return;
    c->done = true;
    if (c->timer) {
        lv_timer_delete(c->timer);
        c->timer = NULL;
    }
    mw_ui_page_destroy(&c->page);
    mw_ui_modal_done(0);
}
static void message_ok_cb(lv_event_t* e) {
    message_close((message_ctx_t*)lv_event_get_user_data(e));
}
static void message_escape(void* user) {
    message_close((message_ctx_t*)user);
}
static void message_timeout_cb(lv_timer_t* t) {
    message_ctx_t* c = (message_ctx_t*)lv_timer_get_user_data(t);
    if (c) message_close(c);
}
static void message_cancel_now(void) { message_close(&s_message); }

static void message_build(void* arg) {
    message_ctx_t* c = (message_ctx_t*)arg;
    c->done = false;
    mw_ui_overlay_create(&c->page, c->title);
    mw_ui_page_set_escape(&c->page, message_escape, c);
    mw_ui_modal_set_cancel(message_cancel_now);

    lv_obj_t* box = make_scroll_body(c->page.body, c->body);
    add_scroll_hint_into(box, c->body);

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    if (!f) return;

    lv_obj_t* b = mw_ui_button(f, TX(XSTR_OK), message_ok_cb, c);
    lv_obj_set_flex_grow(b, 1);

    mw_ui_focus_add(&c->page, b);
    lv_group_focus_obj(b);

    if (c->timeout_ms > 0) {
        c->timer = lv_timer_create(message_timeout_cb, c->timeout_ms, c);
    } else {
        c->timer = NULL;
    }
}

void mw_ui_message(const char* title, const char* body) {
    s_message.title      = title ? title : TX(XSTR_APP_NAME);
    s_message.body       = body  ? body  : "";
    s_message.timeout_ms = 0;
    s_message.timer      = NULL;
    s_message.done       = false;
    (void)mw_ui_modal_call(message_build, &s_message);
}

void mw_ui_message_timeout(const char* title, const char* body,
                           uint32_t timeout_ms) {
    s_message.title      = title ? title : TX(XSTR_APP_NAME);
    s_message.body       = body  ? body  : "";
    s_message.timeout_ms = timeout_ms;
    s_message.timer      = NULL;
    s_message.done       = false;
    (void)mw_ui_modal_call(message_build, &s_message);
}

// ---------------- progress -------------------------------------------------
typedef struct {
    char      title[48];
    char      detail[64];
    int       permille;
    mw_page_t page;
    lv_obj_t* bar;
    lv_obj_t* lbl_detail;
    lv_obj_t* lbl_pct;
    bool      open;
    // Cancel support (mw_ui_progress_cancellable). `cancelled` is written on
    // the LVGL task and read from the crypto task; a plain volatile bool is
    // enough for a one-way flag on the S3.
    bool           cancellable;
    volatile bool  cancelled;
} progress_ctx_t;

static progress_ctx_t s_progress;

static void progress_del_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_progress.open       = false;
    s_progress.bar        = NULL;
    s_progress.lbl_detail = NULL;
    s_progress.lbl_pct    = NULL;
    s_progress.page.scr   = NULL;
}

static void progress_cancel_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_progress.cancelled = true;
}

static void progress_escape(void* user) {
    MW_UNUSED(user);
    s_progress.cancelled = true;
}

static void progress_job(void* arg) {
    progress_ctx_t* c = (progress_ctx_t*)arg;

    if (!c->open) {
        mw_ui_overlay_create(&c->page, c->title);
        lv_obj_add_event_cb(c->page.scr, progress_del_cb, LV_EVENT_DELETE, NULL);

        lv_obj_t* spacer = lv_obj_create(c->page.body);
        lv_obj_remove_style_all(spacer);
        lv_obj_set_width(spacer, lv_pct(100));
        lv_obj_set_flex_grow(spacer, 1);

        c->bar        = mw_ui_bar(c->page.body);
        c->lbl_pct    = mw_ui_label(c->page.body, "", mw_style_dim());
        c->lbl_detail = mw_ui_label(c->page.body, "", mw_style_dim());

        lv_obj_t* spacer2 = lv_obj_create(c->page.body);
        lv_obj_remove_style_all(spacer2);
        lv_obj_set_width(spacer2, lv_pct(100));
        lv_obj_set_flex_grow(spacer2, 1);

        if (c->cancellable) {
            lv_obj_t* footer = mw_ui_page_footer(&c->page);
            lv_obj_t* btn = mw_ui_button(footer, T(STR_CANCEL), progress_cancel_cb, NULL);
            mw_ui_focus_add(&c->page, btn);
            mw_ui_page_set_escape(&c->page, progress_escape, NULL);
        }

        c->open = true;
    } else if (c->page.title) {
        lv_label_set_text(c->page.title, c->title);
    }

    if (c->bar)        lv_bar_set_value(c->bar, c->permille, LV_ANIM_OFF);
    if (c->lbl_pct)    lv_label_set_text_fmt(c->lbl_pct, "%d%%", c->permille / 10);
    if (c->lbl_detail) lv_label_set_text(c->lbl_detail, c->detail);
}

void mw_ui_progress(const char* title, int permille, const char* detail) {
    if (permille < 0)    permille = 0;
    if (permille > 1000) permille = 1000;
    snprintf(s_progress.title, sizeof(s_progress.title), "%s",
             title ? title : TX(XSTR_PROCESSING));
    snprintf(s_progress.detail, sizeof(s_progress.detail), "%s",
             detail ? detail : "");
    s_progress.permille = permille;
    mw_ui_async_call(progress_job, &s_progress);
}

static void progress_close_job(void* arg) {
    MW_UNUSED(arg);
    if (s_progress.open) mw_ui_page_destroy(&s_progress.page);
    s_progress.open = false;
}

void mw_ui_progress_close(void) {
    mw_ui_sync_call(progress_close_job, NULL);
}

void mw_ui_progress_cancellable(bool on) {
    s_progress.cancellable = on;
    s_progress.cancelled   = false;
}

bool mw_ui_progress_cancelled(void) {
    return s_progress.cancelled;
}

// ---------------- chooser --------------------------------------------------
typedef struct {
    const char*        title;
    const char* const* items;
    int                count;
    int                initial;
    mw_page_t          page;
    bool               done;
} choose_ctx_t;

static choose_ctx_t s_choose;

static void choose_finish(int32_t r) {
    if (s_choose.done) return;
    s_choose.done = true;
    mw_ui_page_destroy(&s_choose.page);
    mw_ui_modal_done(r);
}
static void choose_item_cb(lv_event_t* e) {
    const int idx = (int)(intptr_t)lv_event_get_user_data(e);
    mw_ui_focus_remember(MW_FOCUS_CHOOSE, idx);
    choose_finish(idx);
}
static void choose_cancel_cb(lv_event_t* e) { MW_UNUSED(e); choose_finish(-1); }
static void choose_escape(void* user)       { MW_UNUSED(user); choose_finish(-1); }
static void choose_cancel_now(void)          { choose_finish(-1); }

static void choose_build(void* arg) {
    choose_ctx_t* c = (choose_ctx_t*)arg;
    c->done = false;
    mw_ui_overlay_create(&c->page, c->title);
    mw_ui_page_set_escape(&c->page, choose_escape, c);
    mw_ui_modal_set_cancel(choose_cancel_now);

    lv_obj_t* list = mw_ui_list(c->page.body);
    lv_obj_t* focus_row = NULL;
    const int focus_target = mw_ui_focus_restore(MW_FOCUS_CHOOSE);

    for (int i = 0; i < c->count; i++) {
        lv_obj_t* row = mw_ui_list_row(list, NULL, c->items[i], choose_item_cb,
                                       (void*)(intptr_t)i);
        mw_ui_focus_add(&c->page, row);
        if (row && i == focus_target) focus_row = row;
    }

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    if (f) {
        lv_obj_t* b = mw_ui_button(f, T(STR_CANCEL), choose_cancel_cb, c);
        lv_obj_set_flex_grow(b, 1);
        mw_ui_focus_add(&c->page, b);
    }

    if (focus_row)      lv_group_focus_obj(focus_row);
    else if (c->count)  lv_group_focus_obj(lv_obj_get_child(list, 0));
}

int mw_ui_choose(const char* title, const char* const* items, int count,
                 int initial) {
    if (!items || count <= 0) return -1;
    s_choose.title   = title ? title : "";
    s_choose.items   = items;
    s_choose.count   = count;
    s_choose.initial = initial;
    s_choose.done    = false;
    return (int)mw_ui_modal_call(choose_build, &s_choose);
}

// ---------------- full text viewer (TZ 12.3 full address) ------------------
typedef struct {
    const char* title;
    const char* text;
    mw_page_t   page;
    bool        done;
} textview_ctx_t;

static textview_ctx_t s_textview;

static void textview_close(void) {
    if (s_textview.done) return;
    s_textview.done = true;
    mw_ui_page_destroy(&s_textview.page);
    mw_ui_modal_done(0);
}
static void textview_cb(lv_event_t* e)     { MW_UNUSED(e); textview_close(); }
static void textview_escape(void* user)    { MW_UNUSED(user); textview_close(); }
static void textview_cancel_now(void)       { textview_close(); }

static void textview_build(void* arg) {
    textview_ctx_t* c = (textview_ctx_t*)arg;
    c->done = false;
    mw_ui_overlay_create(&c->page, c->title);
    mw_ui_page_set_escape(&c->page, textview_escape, c);
    mw_ui_modal_set_cancel(textview_cancel_now);

    lv_obj_t* box = lv_obj_create(c->page.body);
    lv_obj_remove_style_all(box);
    lv_obj_add_style(box, mw_style_card(), LV_PART_MAIN);
    lv_obj_set_width(box, lv_pct(100));
    lv_obj_set_flex_grow(box, 1);
    lv_obj_set_style_max_height(box, lv_pct(100), LV_PART_MAIN);
    lv_obj_add_flag(box, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(box, LV_DIR_VER);
    MW_OBJ_CLEAR_FLAG(box, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t* l = mw_ui_label(box, c->text, mw_style_mono());
    lv_obj_add_flag(l, LV_OBJ_FLAG_EVENT_BUBBLE);

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    if (!f) return;
    lv_obj_t* b = mw_ui_button(f, TX(XSTR_CLOSE), textview_cb, c);
    lv_obj_set_flex_grow(b, 1);
    mw_ui_focus_add(&c->page, b);
    lv_group_focus_obj(b);
}

void mw_ui_text_view(const char* title, const char* text) {
    s_textview.title = title ? title : "";
    s_textview.text  = text  ? text  : "";
    s_textview.done  = false;
    (void)mw_ui_modal_call(textview_build, &s_textview);
}