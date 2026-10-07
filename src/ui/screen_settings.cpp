// ---------------------------------------------------------------------------
//  Settings (TZ 4.2 "Экран настроек", task2 items 1, 3, 4, 6).
//
//      ┌──────────────────────────────┐
//      │                 SD USB  85%  │
//      │ Настройки                    │
//      │ ┌──────────────────────────┐ │
//      │ │ Тип клавиатуры  Полная   │ │
//      │ │ Раскладка       QWERTY   │ │
//      │ │ Яркость         80%      │ │
//      │ │ Автоблокировка  5 мин    │ │
//      │ │ Проверка сенсора         │ │  (калибровка: только XPT2046)
//      │ │ Форматировать SD         │ │
//      │ │ Язык            Русский  │ │
//      │ │ Сеть            Mainnet  │ │
//      │ │ Отладочный лог  Выкл     │ │
//      │ │ Сменить пароль устройства│ │
//      │ │ Об устройстве            │ │
//      │ │ Сброс устройства         │ │
//      │ └──────────────────────────┘ │
//      │        [← Назад]             │
//      └──────────────────────────────┘
//
//  Every change goes through mw_ui_settings_store(), i.e. mw_settings_save(),
//  so nothing is kept only in RAM. The screen is a loop of single modals -
//  pick a row, handle it, rebuild - which keeps modals from nesting and keeps
//  at most two LVGL screens alive.
//
//  Destructive rows (format, reset) and the eFuse burn go through
//  mw_ui_confirm_code(): the user types a number shown on screen.
//
//  Touch: a capacitive panel has a fixed map and gets a "Touch test" page
//  (crosses, a dot under the reported point, raw -> logical readout); only a
//  resistive XPT2046 gets "Touch calibration".
//
//  Focus memory: the row the user picked is stored in MW_FOCUS_SETTINGS and
//  restored the next time settings_build() runs. s_set_actions[] maps the row
//  index back to the SET_* action, because the list of rows is dynamic.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../wallet/file_store.h"
#include "../hal/log.h"
#include "../config/app_config.h"
#include "../transfer/transfer.h"
#include "../wallet/device_auth.h"
#include "../wallet/session.h"
#include "../crypto/memzero.h"
#include "../hal/touch_map.h"

#include <stdio.h>
#include <string.h>

enum {
    SET_BACK = 0, SET_KB, SET_LAYOUT, SET_BRIGHT, SET_AUTOLOCK, SET_CALIB,
    SET_FORMAT, SET_LANG, SET_NET, SET_DEBUG, SET_PASSWORD, SET_ABOUT,
    SET_EFUSE, SET_RESET, SET_TOUCH_TEST
};

typedef struct {
    mw_page_t     page;
    mw_settings_t s;
} set_ctx_t;

static set_ctx_t s_set;

// Row index -> SET_* action. Filled by settings_build() on every rebuild.
#define SET_MAX_ROWS 16
static int s_set_actions[SET_MAX_ROWS];
static int s_set_count = 0;

static const char* net_name(mw_network_t n) {
    switch (n) {
    case MW_NET_TESTNET:  return TX(XSTR_NET_TEST);
    case MW_NET_STAGENET: return TX(XSTR_NET_STAGE);
    case MW_NET_MAINNET:
    default:              return TX(XSTR_NET_MAIN);
    }
}

// ---------------------------------------------------------------------------
static void set_row_cb(lv_event_t* e) {
    const int idx = (int)(intptr_t)lv_event_get_user_data(e);
    if (idx < 0 || idx >= s_set_count) return;
    // Remember the ROW INDEX, not the SET_* action: the two do not match, and
    // the row list is dynamic (some rows exist only on some boards).
    mw_ui_focus_remember(MW_FOCUS_SETTINGS, idx);
    const int action = s_set_actions[idx];
    MW_LOGD("settings", "row_cb idx=%d action=%d", idx, action);
    mw_ui_page_destroy(&s_set.page);
    mw_ui_modal_done(action);
}

static void set_back_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_ui_page_destroy(&s_set.page);
    mw_ui_modal_done(SET_BACK);
}

static void set_escape(void* user) {
    MW_UNUSED(user);
    mw_ui_page_destroy(&s_set.page);
    mw_ui_modal_done(SET_BACK);
}

static void settings_build(void* arg) {
    set_ctx_t* c = (set_ctx_t*)arg;
    char buf[32];

    mw_ui_page_create(&c->page, T(STR_MAIN_SETTINGS), true);
    mw_ui_page_set_escape(&c->page, set_escape, c);

    lv_obj_t* list = mw_ui_list(c->page.body);
    const int focus_target = mw_ui_focus_restore(MW_FOCUS_SETTINGS);
    lv_obj_t* focus_row = NULL;

    s_set_count = 0;

    auto add = [&](const char* icon, const char* key, const char* value, int action) {
        if (s_set_count >= SET_MAX_ROWS) return;
        char line[80];
        if (value && value[0]) snprintf(line, sizeof(line), "%s: %s", key, value);
        else                   snprintf(line, sizeof(line), "%s", key);
        const int idx = s_set_count;
        s_set_actions[idx] = action;
        lv_obj_t* row = mw_ui_list_row(list, icon, line, set_row_cb,
                                       (void*)(intptr_t)idx);
        mw_ui_focus_add(&c->page, row);
        if (idx == focus_target) focus_row = row;
        s_set_count++;
    };

    add(LV_SYMBOL_KEYBOARD, T(STR_SETTINGS_KEYBOARD),
        (c->s.keyboard == KEYBOARD_SCROLL) ? TX(XSTR_KB_SCROLL) : TX(XSTR_KB_FULL),
        SET_KB);

    // The layout only matters for the touch (full) keyboard.
    if (mw_hal_caps()->has_touch) {
        add(LV_SYMBOL_KEYBOARD, TX(XSTR_KB_LAYOUT),
            (c->s.kb_layout == KB_LAYOUT_ABC) ? TX(XSTR_KB_ABC) : TX(XSTR_KB_QWERTY),
            SET_LAYOUT);
    }

    snprintf(buf, sizeof(buf), "%d%%", (int)c->s.brightness);
    add(LV_SYMBOL_EYE_OPEN, T(STR_SETTINGS_BRIGHTNESS), buf, SET_BRIGHT);

    if (c->s.autolock_min == 0) snprintf(buf, sizeof(buf), "%s", TX(XSTR_NO));
    else snprintf(buf, sizeof(buf), TX(XSTR_MINUTES), (int)c->s.autolock_min);
    add(LV_SYMBOL_POWER,    T(STR_SETTINGS_AUTOLOCK),   buf, SET_AUTOLOCK);

    if (mw_hal_caps()->has_touch) {
        if (mw_touch_needs_calibration())
            add(LV_SYMBOL_EDIT, T(STR_SETTINGS_CALIBRATE), NULL, SET_CALIB);
        else
            add(LV_SYMBOL_EDIT, TX(XSTR_TOUCH_TEST), NULL, SET_TOUCH_TEST);
    }
    if (mw_hal_caps()->has_sd) {
        add(LV_SYMBOL_SD_CARD, T(STR_SETTINGS_FORMAT_SD), NULL, SET_FORMAT);
    }

    add(LV_SYMBOL_BELL,     TX(XSTR_SETTINGS_LANG),
        (mw_i18n_get() == MW_LANG_EN) ? TX(XSTR_LANG_EN) : TX(XSTR_LANG_RU),
        SET_LANG);

    add(LV_SYMBOL_SHUFFLE,  TX(XSTR_SETTINGS_NETWORK),
        net_name(c->s.network), SET_NET);

    add(LV_SYMBOL_LIST,     TX(XSTR_DEBUG_LOG),
        c->s.debug_log ? TX(XSTR_ON) : TX(XSTR_OFF), SET_DEBUG);

    add(LV_SYMBOL_CHARGE,   TX(XSTR_PW_CHANGE), NULL, SET_PASSWORD);

    add(LV_SYMBOL_FILE,     TX(XSTR_SETTINGS_ABOUT), NULL, SET_ABOUT);

    if (mw_secure_key_status() != MW_OK) {
        add(LV_SYMBOL_WARNING, TX(XSTR_EFUSE_PROVISION), NULL, SET_EFUSE);
    }

    add(LV_SYMBOL_TRASH,    T(STR_SETTINGS_RESET), NULL, SET_RESET);

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    lv_obj_t* b = mw_ui_button(f, T(STR_BACK), set_back_cb,
                               (void*)(intptr_t)SET_BACK);
    lv_obj_set_flex_grow(b, 1);
    mw_ui_focus_add(&c->page, b);

    if (focus_row) {
        MW_LOGD("settings", "restore focus to row %d", focus_target);
        lv_group_focus_obj(focus_row);
    }
}

// ---------------------------------------------------------------------------
//  Brightness: a live slider, because a preset list would be a poor fit for a
//  setting the user judges with their eyes.
// ---------------------------------------------------------------------------
typedef struct {
    mw_page_t page;
    lv_obj_t* slider;
    lv_obj_t* lbl;
    uint8_t   value;
    uint8_t   original;
} bright_ctx_t;

static bright_ctx_t s_bright;

static void bright_changed_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_bright.value = (uint8_t)lv_slider_get_value(s_bright.slider);
    if (s_bright.value < 5) s_bright.value = 5;         // never go fully dark
    mw_display_backlight(s_bright.value);
    if (s_bright.lbl) lv_label_set_text_fmt(s_bright.lbl, "%d%%",
                                            (int)s_bright.value);
}
static void bright_ok_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_ui_page_destroy(&s_bright.page);
    mw_ui_modal_done(1);
}
static void bright_cancel_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_display_backlight(s_bright.original);
    mw_ui_page_destroy(&s_bright.page);
    mw_ui_modal_done(0);
}
static void bright_escape(void* user) {
    MW_UNUSED(user);
    bright_cancel_cb(NULL);
}

static void bright_build(void* arg) {
    bright_ctx_t* c = (bright_ctx_t*)arg;
    mw_ui_page_create(&c->page, T(STR_SETTINGS_BRIGHTNESS), true);
    mw_ui_page_set_escape(&c->page, bright_escape, c);

    c->lbl = mw_ui_label(c->page.body, "", NULL);

    c->slider = lv_slider_create(c->page.body);
    lv_obj_set_width(c->slider, lv_pct(100));
    lv_slider_set_range(c->slider, 5, 100);
    lv_slider_set_value(c->slider, c->value, LV_ANIM_OFF);
    lv_obj_add_event_cb(c->slider, bright_changed_cb, LV_EVENT_VALUE_CHANGED,
                        NULL);
    mw_ui_focus_add(&c->page, c->slider);
    lv_group_focus_obj(c->slider);

    lv_label_set_text_fmt(c->lbl, "%d%%", (int)c->value);

    lv_obj_t* f  = mw_ui_page_footer(&c->page);
    lv_obj_t* bc = mw_ui_button(f, T(STR_CANCEL), bright_cancel_cb, NULL);
    lv_obj_t* bo = mw_ui_button(f, T(STR_SAVE),   bright_ok_cb,     NULL);
    lv_obj_set_flex_grow(bc, 1);
    lv_obj_set_flex_grow(bo, 1);
    mw_ui_focus_add(&c->page, bc);
    mw_ui_focus_add(&c->page, bo);
}

static bool brightness_dialog(uint8_t* value) {
    memset(&s_bright, 0, sizeof(s_bright));
    s_bright.value    = (*value < 5) ? 80 : *value;
    s_bright.original = s_bright.value;
    const bool ok = (mw_ui_modal_call(bright_build, &s_bright) == 1);
    if (ok) *value = s_bright.value;
    return ok;
}

// ---------------------------------------------------------------------------
//  eFuse provisioning (TZ 8.1) - irreversible, so behind the typed number.
// ---------------------------------------------------------------------------
bool mw_screen_efuse_provision_run(void) {
    if (mw_secure_key_status() == MW_OK) return true;   // already burned

    if (!mw_ui_confirm(TX(XSTR_EFUSE_PROVISION), TX(XSTR_EFUSE_WARN1),
                       T(STR_NEXT), T(STR_CANCEL))) {
        return false;
    }
    if (!mw_ui_confirm_code(TX(XSTR_EFUSE_PROVISION), TX(XSTR_EFUSE_WARN2))) {
        return false;
    }

    const mw_err_t e = mw_secure_key_provision();
    if (e == MW_OK) {
        MW_LOGI("settings", "eFuse HMAC key provisioned");
        mw_ui_message_timeout(T(STR_SUCCESS), TX(XSTR_EFUSE_DONE), 2000);
        return true;
    }
    MW_LOGE("settings", "eFuse provisioning failed: %s", mw_err_str(e));
    mw_ui_message(T(STR_ERR_GENERIC), mw_err_str(e));
    return false;
}

// ---------------------------------------------------------------------------
//  Touch test (capacitive panels): crosses at the four corners and the
//  centre, a dot under the reported point and a "raw x,y -> x,y" readout.
//  The coordinate trace (debug log only) is on while this page exists and
//  is turned off by the page's own delete handler, whatever closed it.
// ---------------------------------------------------------------------------
typedef struct {
    mw_page_t   page;
    lv_obj_t*   layer;
    lv_obj_t*   dot;
    lv_obj_t*   readout;
    lv_timer_t* timer;
    int32_t     last_rx, last_ry, last_x, last_y;
    bool        last_pressed, shown;
} touch_test_ctx_t;

static touch_test_ctx_t s_tt;

#define TT_DOT 10
#define TT_ARM 8          // half-length of a cross arm

static lv_obj_t* tt_rect(lv_obj_t* parent, int32_t x, int32_t y, int32_t w,
                         int32_t h, lv_color_t col) {
    lv_obj_t* o = lv_obj_create(parent);
    lv_obj_remove_style_all(o);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(o, LV_OBJ_FLAG_IGNORE_LAYOUT);
    lv_obj_set_style_bg_color(o, col, 0);
    lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
    lv_obj_set_pos(o, x, y);
    lv_obj_set_size(o, w, h);
    return o;
}

static void tt_cross(lv_obj_t* parent, int32_t cx, int32_t cy) {
    const lv_color_t c = mw_palette()->text;
    tt_rect(parent, cx - TT_ARM, cy, 2 * TT_ARM + 1, 1, c);
    tt_rect(parent, cx, cy - TT_ARM, 1, 2 * TT_ARM + 1, c);
}

// Latest sample: the driver's own (with raw values) on the device; the LVGL
// pointer on a build whose driver does not report (host simulator).
static bool tt_sample(int32_t* rx, int32_t* ry, int32_t* x, int32_t* y,
                      bool* pressed, bool* have_raw) {
    mw_touch_debug_t d;
    if (mw_touch_debug_last(&d)) {
        *rx = d.raw_x; *ry = d.raw_y; *x = d.x; *y = d.y;
        *pressed = d.pressed; *have_raw = true;
        return true;
    }
#if LVGL_VERSION_MAJOR >= 9
    for (lv_indev_t* in = lv_indev_get_next(NULL); in; in = lv_indev_get_next(in)) {
        if (lv_indev_get_type(in) != LV_INDEV_TYPE_POINTER) continue;
        lv_point_t p;
        lv_indev_get_point(in, &p);
        *rx = 0; *ry = 0; *x = p.x; *y = p.y;
        *pressed = (lv_indev_get_state(in) == LV_INDEV_STATE_PRESSED);
        *have_raw = false;
        return true;
    }
#endif
    return false;
}

static void tt_timer_cb(lv_timer_t* t) {
    MW_UNUSED(t);
    int32_t rx, ry, x, y;
    bool pressed, have_raw;
    if (!tt_sample(&rx, &ry, &x, &y, &pressed, &have_raw)) return;
    if (!pressed && !s_tt.shown) return;        // nothing touched yet
    if (s_tt.shown && pressed == s_tt.last_pressed && rx == s_tt.last_rx &&
        ry == s_tt.last_ry && x == s_tt.last_x && y == s_tt.last_y) return;
    s_tt.shown = true;
    s_tt.last_rx = rx; s_tt.last_ry = ry; s_tt.last_x = x; s_tt.last_y = y;
    s_tt.last_pressed = pressed;

    lv_obj_set_pos(s_tt.dot, x - TT_DOT / 2, y - TT_DOT / 2);
    lv_obj_set_style_bg_color(s_tt.dot, pressed ? mw_palette()->accent
                                                : mw_palette()->text_dim, 0);
    lv_obj_clear_flag(s_tt.dot, LV_OBJ_FLAG_HIDDEN);
    if (have_raw)
        lv_label_set_text_fmt(s_tt.readout, "raw %d,%d -> %d,%d",
                              (int)rx, (int)ry, (int)x, (int)y);
    else
        lv_label_set_text_fmt(s_tt.readout, "raw - -> %d,%d", (int)x, (int)y);
}

static void tt_layer_deleted_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_touch_trace(false);
    if (s_tt.timer) {
        lv_timer_delete(s_tt.timer);
        s_tt.timer = NULL;
    }
    s_tt.layer = NULL;
    s_tt.dot   = NULL;
}

static void tt_done_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_ui_page_destroy(&s_tt.page);
    mw_ui_modal_done(0);
}

static void tt_escape(void* user) {
    MW_UNUSED(user);
    tt_done_cb(NULL);
}

static void touch_test_build(void* arg) {
    touch_test_ctx_t* c = (touch_test_ctx_t*)arg;
    mw_ui_page_create(&c->page, TX(XSTR_TOUCH_TEST), false);
    mw_ui_page_set_escape(&c->page, tt_escape, c);

    lv_obj_t* hint = mw_ui_label(c->page.body, TX(XSTR_TOUCH_TEST_HINT), NULL);
    lv_obj_set_width(hint, lv_pct(100));
    lv_label_set_long_mode(hint, LV_LABEL_LONG_WRAP);
    c->readout = mw_ui_label(c->page.body, TX(XSTR_TOUCH_TEST_WAIT), NULL);

    // Done sits in the middle third, clear of the corner crosses, so testing
    // a bottom corner does not close the page.
    const int32_t w = (int32_t)mw_hal_caps()->width;
    const int32_t h = (int32_t)mw_hal_caps()->height;
    lv_obj_t* f = mw_ui_page_footer(&c->page);
    lv_obj_set_flex_align(f, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_t* b = mw_ui_button(f, T(STR_DONE), tt_done_cb, NULL);
    lv_obj_set_flex_grow(b, 0);
    lv_obj_set_width(b, w / 3);
    mw_ui_focus_add(&c->page, b);

    // Drawing layer over the whole screen. Nothing on it is clickable, so
    // taps still reach the Done button underneath.
    c->layer = lv_obj_create(c->page.scr);
    lv_obj_remove_style_all(c->layer);
    lv_obj_clear_flag(c->layer, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_clear_flag(c->layer, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(c->layer, LV_OBJ_FLAG_IGNORE_LAYOUT);
    lv_obj_add_flag(c->layer, LV_OBJ_FLAG_FLOATING);
    lv_obj_set_pos(c->layer, 0, 0);
    lv_obj_set_size(c->layer, w, h);

    tt_cross(c->layer, 12, 12);
    tt_cross(c->layer, w - 13, 12);
    tt_cross(c->layer, 12, h - 13);
    tt_cross(c->layer, w - 13, h - 13);
    tt_cross(c->layer, w / 2, h / 2);

    c->dot = tt_rect(c->layer, 0, 0, TT_DOT, TT_DOT, mw_palette()->accent);
    lv_obj_set_style_radius(c->dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_add_flag(c->dot, LV_OBJ_FLAG_HIDDEN);

    lv_obj_add_event_cb(c->layer, tt_layer_deleted_cb, LV_EVENT_DELETE, NULL);
    c->timer = lv_timer_create(tt_timer_cb, 30, NULL);
    mw_touch_trace(true);
}

static void touch_test_run(void) {
    memset(&s_tt, 0, sizeof(s_tt));
    (void)mw_ui_modal_call(touch_test_build, &s_tt);
    mw_touch_trace(false);
}

// ---------------------------------------------------------------------------
//  Device password change (task2 item 1)
//
//  The old password is verified as soon as it is typed, so a correct one
//  always resets the failed-attempt counter even when the new password is
//  then cancelled or mistyped. A bad new password re-asks only the new one.
// ---------------------------------------------------------------------------
static mw_err_t ask_password(const char* title, char* out, size_t cap) {
    mw_kb_ctx_t kc;
    memset(&kc, 0, sizeof(kc));
    kc.mode       = MW_KB_MODE_FREE_TEXT;
    kc.type       = mw_ui_settings()->keyboard;
    kc.title      = title;
    kc.allow_back = false;
    return mw_kb_run(&kc, out, cap);
}

// Shows why a device-password check failed. Wrong, locked and empty are user
// outcomes; anything else is a fault and is logged.
static void show_auth_error(mw_err_t e) {
    char msg[96];
    if (e == MW_ERR_DECRYPT) {
        snprintf(msg, sizeof(msg), TX(XSTR_PW_WRONG),
                 (int)mw_device_auth_failed_attempts());
        const uint32_t ms = mw_device_auth_lockout_ms();
        if (ms) {
            const size_t n = strlen(msg);
            snprintf(msg + n, sizeof(msg) - n, "\n");
            snprintf(msg + n + 1, sizeof(msg) - n - 1, TX(XSTR_PW_LOCKED),
                     (int)((ms + 999u) / 1000u));
        }
        mw_ui_message(T(STR_ERR_GENERIC), msg);
    } else if (e == MW_ERR_ABORTED) {
        snprintf(msg, sizeof(msg), TX(XSTR_PW_LOCKED),
                 (int)((mw_device_auth_lockout_ms() + 999u) / 1000u));
        mw_ui_message(T(STR_ERR_GENERIC), msg);
    } else if (e == MW_ERR_INVALID_ARG) {
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_EMPTY));
    } else {
        MW_LOGE("settings", "device password check failed: %s", mw_err_str(e));
        mw_ui_message(T(STR_ERR_GENERIC), mw_err_str(e));
    }
}

// Asks for the new password and its repeat until they agree and follow the
// length rule. False when the user cancels.
static bool ask_new_password(char* new_pw, char* again, size_t cap) {
    for (;;) {
        mw_memzero(new_pw, cap);
        mw_memzero(again, cap);
        if (ask_password(TX(XSTR_PW_NEW), new_pw, cap) != MW_OK) return false;
        const size_t n = strlen(new_pw);
        if (n < MW_DEVICE_PW_MIN || n > MW_DEVICE_PW_MAX) {
            mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_RULES));
            continue;
        }
        if (ask_password(TX(XSTR_PW_REPEAT), again, cap) != MW_OK) return false;
        if (strcmp(new_pw, again) != 0) {
            mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_PW_MISMATCH));
            continue;
        }
        return true;
    }
}

static void change_password(void) {
    char old_pw[MW_DEVICE_PW_MAX + 1];
    char new_pw[MW_DEVICE_PW_MAX + 1];
    char again[MW_DEVICE_PW_MAX + 1];
    memset(old_pw, 0, sizeof(old_pw));
    memset(new_pw, 0, sizeof(new_pw));
    memset(again, 0, sizeof(again));

    if (!mw_device_auth_is_set()) {
        mw_ui_message(TX(XSTR_PW_TITLE), TX(XSTR_PW_REQUIRED));
        return;
    }

    // A running delay would refuse even the correct password: say so before
    // anything is typed, then go back to Settings.
    const uint32_t wait_ms = mw_device_auth_lockout_ms();
    if (wait_ms) {
        char msg[64];
        snprintf(msg, sizeof(msg), TX(XSTR_PW_LOCKED),
                 (int)((wait_ms + 999u) / 1000u));
        mw_ui_message_timeout(T(STR_ERR_GENERIC), msg, wait_ms);
        return;
    }

    do {
        if (ask_password(TX(XSTR_PW_OLD), old_pw, sizeof(old_pw)) != MW_OK) break;

        mw_ui_progress(TX(XSTR_PW_CHECKING), 0, NULL);
        mw_err_t e = mw_device_auth_verify(old_pw);
        mw_ui_progress_close();
        if (e != MW_OK) {
            show_auth_error(e);
            break;
        }

        if (!ask_new_password(new_pw, again, sizeof(new_pw))) break;

        mw_ui_progress(TX(XSTR_PW_CHANGE), 0, NULL);
        e = mw_device_auth_change(old_pw, new_pw);
        mw_ui_progress_close();

        if (e == MW_OK) {
            MW_LOGI("settings", "device password changed, wallets re-keyed");
            mw_ui_message(T(STR_SUCCESS), TX(XSTR_PW_CHANGED));
        } else {
            show_auth_error(e);
        }
    } while (0);

    mw_memzero(old_pw, sizeof(old_pw));
    mw_memzero(new_pw, sizeof(new_pw));
    mw_memzero(again, sizeof(again));
    mw_session_wipe_input();
}

// ---------------------------------------------------------------------------
void mw_screen_settings_run(void) {
    s_set.s = *mw_ui_settings();

    for (;;) {
        const int32_t action = mw_ui_modal_call(settings_build, &s_set);
        bool dirty = false;

        switch (action) {

        case SET_KB: {
            const char* items[] = { TX(XSTR_KB_FULL), TX(XSTR_KB_SCROLL) };
            const int i = mw_ui_choose(T(STR_SETTINGS_KEYBOARD), items, 2,
                                       (int)s_set.s.keyboard);
            if (i >= 0) { s_set.s.keyboard = (keyboard_type_t)i; dirty = true; }
            break;
        }

        case SET_LAYOUT: {
            const char* items[] = { TX(XSTR_KB_QWERTY), TX(XSTR_KB_ABC) };
            const int i = mw_ui_choose(TX(XSTR_KB_LAYOUT), items, 2,
                                       (int)s_set.s.kb_layout);
            if (i >= 0) { s_set.s.kb_layout = (kb_layout_t)i; dirty = true; }
            break;
        }

        case SET_BRIGHT:
            if (brightness_dialog(&s_set.s.brightness)) dirty = true;
            break;

        case SET_AUTOLOCK: {
            static const uint16_t mins[] = { 0, 1, 2, 5, 10, 30 };
            char        labels[6][16];
            const char* items[6];
            for (int i = 0; i < 6; i++) {
                if (mins[i] == 0) snprintf(labels[i], sizeof(labels[i]), "%s",
                                           TX(XSTR_NO));
                else snprintf(labels[i], sizeof(labels[i]), TX(XSTR_MINUTES),
                              (int)mins[i]);
                items[i] = labels[i];
            }
            int cur = 3;
            for (int i = 0; i < 6; i++) if (mins[i] == s_set.s.autolock_min) cur = i;
            const int i = mw_ui_choose(T(STR_SETTINGS_AUTOLOCK), items, 6, cur);
            if (i >= 0) { s_set.s.autolock_min = mins[i]; dirty = true; }
            break;
        }

        case SET_CALIB: {
            mw_ui_message(T(STR_SETTINGS_CALIBRATE), TX(XSTR_CALIB_PROMPT));
            int32_t coeffs[6];
            // The LVGL lock keeps the UI task from polling the panel and
            // flushing over the targets; it is released before any message.
            mw_ui_lock();
            const mw_err_t e = mw_touch_calibrate(coeffs);
#if LVGL_VERSION_MAJOR >= 9
            lv_obj_invalidate(lv_screen_active());
#else
            lv_obj_invalidate(lv_scr_act());
#endif
            mw_ui_unlock();
            if (e == MW_OK) {
                // mw_touch_calibrate() stored coefficients, flag and geometry
                // tag; take the whole record so the save below keeps the tag.
                mw_settings_t st;
                if (mw_settings_load(&st) == MW_OK) {
                    memcpy(s_set.s.touch_calib, st.touch_calib,
                           sizeof(s_set.s.touch_calib));
                    s_set.s.touch_calibrated = st.touch_calibrated;
                    memcpy(s_set.s.touch_cal_tag, st.touch_cal_tag,
                           sizeof(s_set.s.touch_cal_tag));
                } else {
                    memcpy(s_set.s.touch_calib, coeffs, sizeof(coeffs));
                    s_set.s.touch_calibrated = true;
                }
                dirty = true;
                mw_ui_message_timeout(T(STR_SETTINGS_CALIBRATE),
                                      TX(XSTR_CALIB_DONE), 2000);
            } else {
                MW_LOGE("settings", "touch calibration failed: %s", mw_err_str(e));
                mw_ui_message(T(STR_ERR_GENERIC),
                              e == MW_ERR_RANGE ? TX(XSTR_CALIB_FAILED) : mw_err_str(e));
            }
            break;
        }

        case SET_TOUCH_TEST:
            touch_test_run();
            break;

        case SET_FORMAT:
            if (!mw_sd_present()) {
                mw_ui_message(T(STR_ERR_GENERIC), T(STR_NO_SD));
            } else if (mw_ui_confirm_code(T(STR_SETTINGS_FORMAT_SD),
                                          TX(XSTR_FORMAT_SD_Q))) {
                const mw_err_t e = mw_sd_format();
                MW_LOGI("settings", "SD format -> %s", mw_err_str(e));
                mw_ui_message(e == MW_OK ? T(STR_SUCCESS) : T(STR_ERR_GENERIC),
                              e == MW_OK ? T(STR_SUCCESS) : mw_err_str(e));
            }
            break;

        case SET_LANG: {
#if MW_UI_HAS_CYRILLIC_FONT
            const char* items[] = { TX(XSTR_LANG_RU), TX(XSTR_LANG_EN) };
            const int i = mw_ui_choose(TX(XSTR_SETTINGS_LANG), items, 2,
                                       (int)mw_i18n_get());
            if (i >= 0) mw_i18n_set((mw_lang_t)i);
#else
            const char* items[] = { TX(XSTR_LANG_EN) };
            if (mw_ui_choose(TX(XSTR_SETTINGS_LANG), items, 1, 0) >= 0) {
                mw_i18n_set(MW_LANG_EN);
            }
#endif
            break;
        }

        case SET_NET: {
            const char* items[] = { TX(XSTR_NET_MAIN), TX(XSTR_NET_TEST),
                                    TX(XSTR_NET_STAGE) };
            const int i = mw_ui_choose(TX(XSTR_SETTINGS_NETWORK), items, 3,
                                       (int)s_set.s.network);
            if (i >= 0) { s_set.s.network = (mw_network_t)i; dirty = true; }
            break;
        }

        case SET_DEBUG: {
            const char* items[] = { TX(XSTR_OFF), TX(XSTR_ON) };
            const int i = mw_ui_choose(TX(XSTR_DEBUG_LOG), items, 2,
                                       s_set.s.debug_log ? 1 : 0);
            if (i >= 0) {
                s_set.s.debug_log = (i == 1);
                mw_log_set_debug(s_set.s.debug_log);
                MW_LOGI("settings", "debug log %s", s_set.s.debug_log ? "on" : "off");
                dirty = true;
            }
            break;
        }

        case SET_PASSWORD:
            change_password();
            break;

        case SET_ABOUT: {
            char body[224];
            const mw_hal_caps_t* c = mw_hal_caps();
            snprintf(body, sizeof(body),
                     "%s %s\n%s\n%ux%u%s\n%s",
                     TX(XSTR_APP_NAME), MW_FIRMWARE_VERSION,
                     c->board_name ? c->board_name : "",
                     (unsigned)c->width, (unsigned)c->height,
                     c->monochrome ? " mono" : "",
                     (mw_secure_key_status() == MW_OK) ? ""
                                                       : TX(XSTR_EFUSE_MISSING));
            mw_ui_message(TX(XSTR_SETTINGS_ABOUT), body);
            break;
        }

        case SET_EFUSE:
            mw_screen_efuse_provision_run();
            break;

        case SET_RESET:
            if (mw_ui_confirm_code(T(STR_SETTINGS_RESET), T(STR_RESET_CONFIRM))) {
                MW_LOGE("settings", "factory reset requested by the user");
                (void)mw_device_auth_erase();
                // Key image caches (FAT partition) go too; they are sealed under
                // the device key, but nothing of a wallet may survive a reset.
                (void)mw_fstore_wipe_all();
                mw_factory_reset();      // wipes NVS and reboots; never returns
            }
            break;

        case SET_BACK:
        default:
            return;
        }

        if (dirty) {
            if (mw_ui_settings_store(&s_set.s) == MW_OK) {
                mw_ui_message_timeout(T(STR_MAIN_SETTINGS),
                                      TX(XSTR_SETTINGS_SAVED), 1500);
            } else {
                mw_ui_message(T(STR_ERR_GENERIC), T(STR_ERR_GENERIC));
            }
        }
    }
}
