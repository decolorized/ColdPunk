// ---------------------------------------------------------------------------
//  Root screens (task 3).
//
//  The root screen is only a background now: every interactive screen - the
//  game, the password prompt, the menus - is a page run by the crypto task
//  (flows.cpp). It shows nothing that names the wallet, because the device
//  presents itself as a Minesweeper game until it is unlocked.
//
//  Group lifetime note: the keypad indev ALWAYS points at a live group.
//  root_group_reset() creates and installs the new group before the old
//  screen (and its group) is deleted; root_del_cb() only deletes the group it
//  was bound to via user_data.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../hal/log.h"

static lv_group_t* s_root_group = NULL;

static void root_del_cb(lv_event_t* e) {
    lv_group_t* g = (lv_group_t*)lv_event_get_user_data(e);
    if (!g) return;
    if (s_root_group == g) s_root_group = NULL;
    MW_GROUP_DEL(g);
}

static void root_group_reset(lv_obj_t* scr) {
    lv_group_t* g_new = lv_group_create();
    mw_ui_group_activate(g_new);
    s_root_group = g_new;
    lv_obj_add_event_cb(scr, root_del_cb, LV_EVENT_DELETE, g_new);
}

static void plain_background(lv_obj_t* scr, const char* text) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_set_style_pad_all(scr, m->pad, LV_PART_MAIN);
    lv_obj_set_flex_flow(scr, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(scr, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    MW_OBJ_CLEAR_FLAG(scr, LV_OBJ_FLAG_SCROLLABLE);
    if (text && text[0]) {
        lv_obj_t* l = mw_ui_label(scr, text, mw_style_dim());
        lv_obj_set_style_text_align(l, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    }
}

void mw_screen_boot_build(lv_obj_t* scr) {
    plain_background(scr, TX(XSTR_BOOT));
    MW_LOGD("main", "boot screen");
}

void mw_screen_main_build(lv_obj_t* scr) {
    root_group_reset(scr);
    plain_background(scr, NULL);
    MW_LOGD("main", "root background");
}
