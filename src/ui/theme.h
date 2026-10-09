// ---------------------------------------------------------------------------
//  Dark theme + resolution-adaptive metrics (TZ 4.1).
//
//  Every layout decision in the UI comes from the single mw_metrics_t struct
//  computed once at boot from mw_hal_caps(). There is deliberately NO
//  per-board #ifdef anywhere in src/ui: the same binary logic must lay out
//  sensibly on 128x64 monochrome, 240x240, 240x320, 320x480 and 480x480.
//
//  This header also carries the LVGL 8.x / 9.x compatibility shims used by
//  the whole UI layer. The code targets LVGL 9 names; the 8.x branch is only
//  a fallback so the firmware still builds against an older Arduino library.
// ---------------------------------------------------------------------------
#ifndef MW_UI_THEME_H
#define MW_UI_THEME_H

#include <lvgl.h>
#include "i18n.h"
#include "../hal/hal.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// LVGL 8 / 9 compatibility
// ---------------------------------------------------------------------------
#ifndef LVGL_VERSION_MAJOR
#error "lvgl.h did not define LVGL_VERSION_MAJOR - is the LVGL library on the include path?"
#endif

#if LVGL_VERSION_MAJOR >= 9
  #define MW_SCR_LOAD(s)           lv_screen_load(s)
  #define MW_SCR_ACT()             lv_screen_active()
  #define MW_OBJ_DEL(o)            lv_obj_delete(o)
  #define MW_OBJ_DEL_ASYNC(o)      lv_obj_delete_async(o)
  #define MW_OBJ_CLEAR_FLAG(o, f)  lv_obj_remove_flag((o), (f))
  #define MW_OBJ_CLEAR_STATE(o, s) lv_obj_remove_state((o), (s))
  #define MW_BTN_CREATE(p)         lv_button_create(p)
  #define MW_LIST_ADD_BTN(l, i, t) lv_list_add_button((l), (i), (t))
  #define MW_TIMER_USER(t)         lv_timer_get_user_data(t)
  #define MW_TIMER_DEL(t)          lv_timer_delete(t)
  #define MW_GROUP_DEL(g)          lv_group_delete(g)
  #define MW_DISP_SET_THEME(d, t)  lv_display_set_theme((d), (t))
  typedef lv_display_t             mw_lv_disp_t;
#else
  #define MW_SCR_LOAD(s)           lv_scr_load(s)
  #define MW_SCR_ACT()             lv_scr_act()
  #define MW_OBJ_DEL(o)            lv_obj_del(o)
  #define MW_OBJ_DEL_ASYNC(o)      lv_obj_del_async(o)
  #define MW_OBJ_CLEAR_FLAG(o, f)  lv_obj_clear_flag((o), (f))
  #define MW_OBJ_CLEAR_STATE(o, s) lv_obj_clear_state((o), (s))
  #define MW_BTN_CREATE(p)         lv_btn_create(p)
  #define MW_LIST_ADD_BTN(l, i, t) lv_list_add_btn((l), (i), (t))
  #define MW_TIMER_USER(t)         ((t)->user_data)
  #define MW_TIMER_DEL(t)          lv_timer_del(t)
  #define MW_GROUP_DEL(g)          lv_group_del(g)
  #define MW_DISP_SET_THEME(d, t)  lv_disp_set_theme((d), (t))
  typedef lv_disp_t                mw_lv_disp_t;
#endif

// LVGL 9 returns void* from lv_event_get_target(); the cast is a no-op on 8.x.
#define MW_EVT_OBJ(e)    ((lv_obj_t*)lv_event_get_target(e))
#define MW_EVT_CUR(e)    ((lv_obj_t*)lv_event_get_current_target(e))

#define MW_UNUSED(x)     ((void)(x))

// ---------------------------------------------------------------------------
// Cyrillic font (TZ 4.1)
// ---------------------------------------------------------------------------
#if MW_UI_HAS_CYRILLIC_FONT
extern const lv_font_t mw_font_ru_12;
extern const lv_font_t mw_font_ru_14;
extern const lv_font_t mw_font_ru_18;
extern const lv_font_t mw_font_ru_24;
#endif

// ---------------------------------------------------------------------------
// Palette (dark theme)
// ---------------------------------------------------------------------------
typedef struct {
    lv_color_t bg;         // screen background
    lv_color_t surface;    // cards, key caps
    lv_color_t surface2;   // pressed / focused key caps
    lv_color_t text;
    lv_color_t text_dim;   // secondary text and disabled keys
    lv_color_t accent;     // Monero orange
    lv_color_t danger;
    lv_color_t ok;
    lv_color_t warn;
    lv_color_t border;

    // Focus styling. On colour panels the focused object gets an outline in
    // focus_outline. On monochrome panels focus_invert is true and the object
    // is drawn inverted: focus_bg as background, focus_text as foreground.
    lv_color_t focus_outline;
    lv_color_t focus_bg;
    lv_color_t focus_text;
    bool       focus_invert;
} mw_palette_t;

// ---------------------------------------------------------------------------
// Resolution tiers. Nothing outside theme.cpp may switch on the raw
// resolution; use the derived fields instead.
// ---------------------------------------------------------------------------
typedef enum {
    MW_TIER_TINY = 0,   // 128x64 monochrome, buttons only
    MW_TIER_SMALL,      // 240x240 (round or square)
    MW_TIER_MEDIUM,     // 240x320 and 320x240
    MW_TIER_LARGE,      // 320x480 (short side up to 360)
    MW_TIER_XLARGE      // 480x480
} mw_tier_t;

typedef struct {
    uint16_t   w, h;
    bool       mono;
    bool       touch;
    bool       buttons;
    mw_tier_t  tier;
    bool       compact;        // MW_TIER_TINY: no status bar, one-line rows
    bool       landscape;      // w > h

    lv_coord_t pad;            // outer padding of a page
    lv_coord_t gap;            // spacing between siblings
    lv_coord_t row_h;          // menu / list row height (>= 40 on colour, TZ 4.1)
    lv_coord_t btn_h;          // ordinary push button height
    lv_coord_t status_h;       // status bar height (0 when compact)
    lv_coord_t title_h;
    lv_coord_t bar_h;          // keyboard header row and its buttons (= row_h)

    // Keyboard geometry. kb_key_w/h are hints for a 6x5 grid only: the
    // keyboards measure the room that is really left and size their keys.
    lv_coord_t kb_key_w, kb_key_h;
    uint8_t    kb_cols, kb_rows;
    uint8_t    cand_cols, cand_rows;   // candidate word grid
    lv_coord_t cand_h;                 // height of one candidate button
    uint8_t    scroll_visible;         // 3..5 letters visible at once
    bool       kb_footer;              // always false: Back/Clear are in the header

    const lv_font_t* font_small;
    const lv_font_t* font_body;
    const lv_font_t* font_title;
    const lv_font_t* font_mono;        // seed words, addresses, hex
} mw_metrics_t;

// Builds the palette + metrics and installs the dark theme on `disp`.
void mw_theme_init(mw_lv_disp_t* disp);

const mw_metrics_t* mw_metrics(void);
const mw_palette_t* mw_palette(void);
const lv_font_t* mw_font_seed_word(void);   // font for seed words on the seed screens

// Shared styles. They are owned by theme.cpp and live for the whole run.
lv_style_t* mw_style_page(void);       // screen background
lv_style_t* mw_style_card(void);       // rounded surface container
lv_style_t* mw_style_title(void);
lv_style_t* mw_style_dim(void);
lv_style_t* mw_style_mono(void);       // address / seed word text
lv_style_t* mw_style_key(void);        // keyboard key cap
lv_style_t* mw_style_key_dead(void);   // key that cannot extend the prefix
lv_style_t* mw_style_focus(void);      // lv_group focus ring for button boards
lv_style_t* mw_style_pressed(void);    // touch feedback while a finger is down
lv_style_t* mw_style_seed_current(void);   // highlighted seed word (first visible)

// Convenience: applies the standard button look and guarantees the TZ 4.1
// minimum touch target on colour screens.
void mw_theme_button(lv_obj_t* btn);
void mw_theme_danger_button(lv_obj_t* btn);
// Standard button look at an exact size: padding and the minimum sizes are
// zeroed. For key caps, candidates and grid cells whose size is computed.
void mw_theme_button_fixed(lv_obj_t* btn, lv_coord_t w, lv_coord_t h);

#ifdef __cplusplus
}
#endif
#endif