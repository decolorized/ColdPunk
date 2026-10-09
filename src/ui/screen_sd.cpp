// ---------------------------------------------------------------------------
//  SD card file list (wallet menu -> SD card files).
//
//  Two lines per file:
//      [icon] file name                       (ellipsis when it does not fit;
//                                              the focused row scrolls it)
//      Outputs . 12 KB . 2026-10-08 14:23 . done
//
//  On the 320x240 landscape panel (ES3C28P, body font Montserrat 14) a row has
//  about 290 px for the name: typical Feather names - "<wallet>_<10 digits>_
//  outputs", "<10 digits>_unsigned_monero_tx" - are 210..245 px wide and fit
//  in full; only long wallet names get the ellipsis.
//
//  The flow (flows.cpp) builds the rows; this file only shows them and
//  returns the chosen index, or -1.
//
//  SPDX-License-Identifier: MIT
// ---------------------------------------------------------------------------
#include "screen_common.h"

typedef struct {
    const char*            title;
    const mw_sd_row_t*     rows;
    int                    count;
    int                    initial;
    mw_page_t              page;
    bool                   done;
} sd_ctx_t;

static sd_ctx_t s_sd;

static void sd_finish(int32_t r) {
    if (s_sd.done) return;
    s_sd.done = true;
    mw_ui_page_destroy(&s_sd.page);
    mw_ui_modal_done(r);
}
static void sd_row_cb(lv_event_t* e)   { sd_finish((int32_t)(intptr_t)lv_event_get_user_data(e)); }
static void sd_cancel_cb(lv_event_t* e) { MW_UNUSED(e); sd_finish(-1); }
static void sd_escape(void* user)       { MW_UNUSED(user); sd_finish(-1); }
static void sd_cancel_now(void)          { sd_finish(-1); }

// The name scrolls only while its row has the focus; otherwise it ends in "...".
static void sd_focus_cb(lv_event_t* e) {
    lv_obj_t* name = (lv_obj_t*)lv_event_get_user_data(e);
    if (!name) return;
    const lv_event_code_t code = lv_event_get_code(e);
    lv_label_set_long_mode(name, code == LV_EVENT_FOCUSED ? LV_LABEL_LONG_SCROLL_CIRCULAR
                                                          : LV_LABEL_LONG_DOT);
}

static void sd_build(void* arg) {
    sd_ctx_t* c = (sd_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();
    c->done = false;
    mw_ui_overlay_create(&c->page, c->title);
    mw_ui_page_set_escape(&c->page, sd_escape, c);
    mw_ui_modal_set_cancel(sd_cancel_now);

    lv_obj_t* list = mw_ui_list(c->page.body);
    lv_obj_t* focus_row = NULL;

    for (int i = 0; i < c->count; i++) {
        const mw_sd_row_t* r = &c->rows[i];
        lv_obj_t* row = MW_BTN_CREATE(list);
        lv_obj_set_width(row, lv_pct(100));
        lv_obj_set_height(row, LV_SIZE_CONTENT);
        lv_obj_set_style_min_height(row, m->row_h, LV_PART_MAIN);
        lv_obj_set_style_pad_hor(row, m->pad, LV_PART_MAIN);
        lv_obj_set_style_pad_ver(row, m->mono ? 0 : 2, LV_PART_MAIN);
        lv_obj_set_style_pad_row(row, 0, LV_PART_MAIN);
        lv_obj_set_flex_flow(row, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_bg_color(row, mw_palette()->surface, LV_PART_MAIN);
        lv_obj_set_style_bg_opa(row, LV_OPA_COVER, LV_PART_MAIN);
        lv_obj_set_style_bg_color(row, mw_palette()->surface2,
                                  LV_PART_MAIN | LV_STATE_PRESSED);
        lv_obj_set_style_radius(row, m->mono ? 0 : 4, LV_PART_MAIN);
        lv_obj_set_style_shadow_width(row, 0, LV_PART_MAIN);
        lv_obj_add_style(row, mw_style_focus(), LV_PART_MAIN | LV_STATE_FOCUSED);
        lv_obj_add_flag(row, LV_OBJ_FLAG_EVENT_BUBBLE);
        MW_OBJ_CLEAR_FLAG(row, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t* name = lv_label_create(row);
        lv_obj_set_width(name, lv_pct(100));
        lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);
        lv_obj_set_style_text_font(name, m->font_body, LV_PART_MAIN);
        lv_obj_set_style_text_color(name, r->done ? mw_palette()->text_dim : mw_palette()->text,
                                    LV_PART_MAIN);
        lv_label_set_text_fmt(name, "%s %s", r->icon ? r->icon : "", r->name ? r->name : "");

        lv_obj_t* sub = lv_label_create(row);
        lv_obj_set_width(sub, lv_pct(100));
        lv_label_set_long_mode(sub, LV_LABEL_LONG_DOT);
        lv_obj_set_style_text_font(sub, m->font_small, LV_PART_MAIN);
        lv_obj_set_style_text_color(sub, r->done ? mw_palette()->ok : mw_palette()->text_dim,
                                    LV_PART_MAIN);
        lv_label_set_text(sub, r->detail ? r->detail : "");

        lv_obj_add_event_cb(row, sd_row_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);
        lv_obj_add_event_cb(row, sd_focus_cb, LV_EVENT_FOCUSED, name);
        lv_obj_add_event_cb(row, sd_focus_cb, LV_EVENT_DEFOCUSED, name);
        mw_ui_focus_add(&c->page, row);
        if (i == c->initial) focus_row = row;
    }

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    if (f) {
        lv_obj_t* b = mw_ui_button(f, T(STR_BACK), sd_cancel_cb, c);
        lv_obj_set_flex_grow(b, 1);
        mw_ui_focus_add(&c->page, b);
    }
    if (focus_row)     lv_group_focus_obj(focus_row);
    else if (c->count) lv_group_focus_obj(lv_obj_get_child(list, 0));
}

int mw_screen_sd_files_run(const char* title, const mw_sd_row_t* rows, int count,
                           int initial) {
    if (!rows || count <= 0) return -1;
    s_sd.title   = title ? title : "";
    s_sd.rows    = rows;
    s_sd.count   = count;
    s_sd.initial = initial;
    s_sd.done    = false;
    return (int)mw_ui_modal_call(sd_build, &s_sd);
}
