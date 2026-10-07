// ---------------------------------------------------------------------------
//  Dark theme + resolution-adaptive metrics (TZ 4.1).
//
//  Every layout decision in the UI comes from the single mw_metrics_t struct
//  computed once at boot from mw_hal_caps(). There is deliberately NO
//  per-board #ifdef anywhere in src/ui: the same binary logic must lay out
//  sensibly on 128x64 monochrome, 240x240, 240x320, 320x480 and 480x480.
//
//  Row / button heights are derived from the font size plus a small padding,
//  so shrinking a font automatically shrinks the menu items that use it.
//
//  Tiers come from the SHORT side, so 320x240 and 240x320 share a tier.
//  Fonts (small/body/title/mono):
//    TINY 10/12/12/10, SMALL and MEDIUM 12/14/16/12,
//    LARGE 16/20/24/16, XLARGE 18/24/28/24
//  Colour tiers keep a 40 px minimum touch target (32 on SMALL).
//
//  Cyrillic is not used: MW_UI_HAS_CYRILLIC_FONT is 0, so mw_font_for()
//  falls through to the built-in Montserrat faces.
// ---------------------------------------------------------------------------
#include "theme.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Font selection
// ---------------------------------------------------------------------------

// Largest built-in Montserrat face that is <= `px`.
static const lv_font_t* mw_font_montserrat(int px) {
    const lv_font_t* f = LV_FONT_DEFAULT;
#if LV_FONT_MONTSERRAT_8
    if (px >= 8)  f = &lv_font_montserrat_8;
#endif
#if LV_FONT_MONTSERRAT_10
    if (px >= 10) f = &lv_font_montserrat_10;
#endif
#if LV_FONT_MONTSERRAT_12
    if (px >= 12) f = &lv_font_montserrat_12;
#endif
#if LV_FONT_MONTSERRAT_14
    if (px >= 14) f = &lv_font_montserrat_14;
#endif
#if LV_FONT_MONTSERRAT_16
    if (px >= 16) f = &lv_font_montserrat_16;
#endif
#if LV_FONT_MONTSERRAT_18
    if (px >= 18) f = &lv_font_montserrat_18;
#endif
#if LV_FONT_MONTSERRAT_20
    if (px >= 20) f = &lv_font_montserrat_20;
#endif
#if LV_FONT_MONTSERRAT_24
    if (px >= 24) f = &lv_font_montserrat_24;
#endif
#if LV_FONT_MONTSERRAT_28
    if (px >= 28) f = &lv_font_montserrat_28;
#endif
    return f;
}

static const lv_font_t* mw_font_for(int px) {
    return mw_font_montserrat(px);
}

// ---------------------------------------------------------------------------
// Size helpers: derive heights from the font size.
// ---------------------------------------------------------------------------
#define MW_ROW_EXTRA    6
#define MW_BTN_EXTRA    8
#define MW_TITLE_EXTRA  4
#define MW_STATUS_EXTRA 4

static lv_coord_t mw_row_h_for(int font_px)    { return (lv_coord_t)(font_px + MW_ROW_EXTRA);    }
static lv_coord_t mw_btn_h_for(int font_px)    { return (lv_coord_t)(font_px + MW_BTN_EXTRA);    }
static lv_coord_t mw_title_h_for(int font_px)  { return (lv_coord_t)(font_px + MW_TITLE_EXTRA);  }
static lv_coord_t mw_status_h_for(int font_px) { return (lv_coord_t)(font_px + MW_STATUS_EXTRA); }

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static mw_metrics_t s_m;
static mw_palette_t s_p;
static bool         s_ready = false;

static lv_style_t s_st_page;
static lv_style_t s_st_card;
static lv_style_t s_st_title;
static lv_style_t s_st_dim;
static lv_style_t s_st_mono;
static lv_style_t s_st_key;
static lv_style_t s_st_key_dead;
static lv_style_t s_st_focus;
static lv_style_t s_st_seed_current;

// ---------------------------------------------------------------------------
static mw_tier_t tier_for(uint16_t w, uint16_t h, bool mono) {
    const uint16_t s = (w < h) ? w : h;   // short side
    const uint16_t l = (w < h) ? h : w;   // long side
    if (mono || s <= 128 || l <= 96) return MW_TIER_TINY;
    if (s <= 240) return (l <= 260) ? MW_TIER_SMALL : MW_TIER_MEDIUM;
    if (s <= 360) return MW_TIER_LARGE;
    return MW_TIER_XLARGE;
}

static void build_palette(bool mono) {
    if (mono) {
        s_p.bg       = lv_color_black();
        s_p.surface  = lv_color_black();
        s_p.surface2 = lv_color_white();
        s_p.text     = lv_color_white();
        s_p.text_dim = lv_color_white();
        s_p.accent   = lv_color_white();
        s_p.danger   = lv_color_white();
        s_p.ok       = lv_color_white();
        s_p.warn     = lv_color_white();
        s_p.border   = lv_color_white();

        // Monochrome focus: invert the focused object (white bg, black fg).
        s_p.focus_invert  = true;
        s_p.focus_bg      = lv_color_white();
        s_p.focus_text    = lv_color_black();
        s_p.focus_outline = lv_color_white();
        return;
    }
    // task2 item 14: higher contrast. Surfaces sit well above the background,
    // secondary text stays readable (>= 7:1 on the background) and every
    // surface has a visible edge.
    s_p.bg       = lv_color_hex(0x0A0A0C);
    s_p.surface  = lv_color_hex(0x2A2A32);
    s_p.surface2 = lv_color_hex(0x40404A);
    s_p.text     = lv_color_hex(0xFFFFFF);
    s_p.text_dim = lv_color_hex(0xC4C4CE);
    s_p.accent   = lv_color_hex(0xFF7A1A);   // Monero orange, a shade brighter
    s_p.danger   = lv_color_hex(0xF04438);
    s_p.ok       = lv_color_hex(0x3DD17E);
    s_p.warn     = lv_color_hex(0xFFC043);
    s_p.border   = lv_color_hex(0x6A6A78);

    // Colour focus: fill the whole object with the accent colour.
    s_p.focus_invert  = false;
    s_p.focus_bg      = s_p.accent;
    s_p.focus_text    = lv_color_white();
    s_p.focus_outline = s_p.accent;
}

static void build_metrics(const mw_hal_caps_t* c) {
    memset(&s_m, 0, sizeof(s_m));
    s_m.w       = c->width;
    s_m.h       = c->height;
    s_m.mono    = c->monochrome;
    s_m.touch   = c->has_touch;
    s_m.buttons = c->has_buttons || c->has_encoder || !c->has_touch;
    s_m.tier    = tier_for(c->width, c->height, c->monochrome);
    s_m.compact = (s_m.tier == MW_TIER_TINY);
    s_m.landscape = (c->width > c->height);

    s_m.kb_cols = 6;
    s_m.kb_rows = 5;

    // Font sizes per tier. Everything else is derived from these.
    int f_small, f_body, f_title, f_mono;

    switch (s_m.tier) {
    case MW_TIER_TINY:
        s_m.pad = 1; s_m.gap = 1;
        s_m.scroll_visible = 5;
        s_m.kb_footer = false;
        s_m.cand_cols = 1; s_m.cand_rows = 3;
        f_small = 10; f_body = 12; f_title = 12; f_mono = 10;
        break;

    case MW_TIER_SMALL:
        s_m.pad = 3; s_m.gap = 2;
        s_m.scroll_visible = 4;
        s_m.kb_footer = false;
        s_m.cand_cols = 2; s_m.cand_rows = 1;
        f_small = 12; f_body = 14; f_title = 16; f_mono = 12;
        break;

    case MW_TIER_MEDIUM:
        s_m.pad = 4; s_m.gap = 3;
        s_m.scroll_visible = 5;
        s_m.kb_footer = false;
        s_m.cand_cols = 3; s_m.cand_rows = 1;
        f_small = 12; f_body = 14; f_title = 16; f_mono = 12;
        break;

    case MW_TIER_LARGE:
        s_m.pad = 6; s_m.gap = 6;
        s_m.scroll_visible = 5;
        s_m.kb_footer = false;
        s_m.cand_cols = 3; s_m.cand_rows = 1;
        f_small = 16; f_body = 20; f_title = 24; f_mono = 16;
        break;

    case MW_TIER_XLARGE:
    default:
        s_m.pad = 8; s_m.gap = 8;
        s_m.scroll_visible = 5;
        s_m.kb_footer = false;
        s_m.cand_cols = 3; s_m.cand_rows = 2;
        f_small = 18; f_body = 24; f_title = 28; f_mono = 24;
        break;
    }

    // Resolve fonts.
    s_m.font_small = mw_font_for(f_small);
    s_m.font_body  = mw_font_for(f_body);
    s_m.font_title = mw_font_for(f_title);
    s_m.font_mono  = mw_font_for(f_mono);

    // Derive heights from fonts.
    s_m.row_h    = mw_row_h_for(f_body);
    s_m.btn_h    = mw_btn_h_for(f_body);
    s_m.title_h  = mw_title_h_for(f_title);
    s_m.status_h = s_m.compact ? 0 : mw_status_h_for(f_small);

    // TZ 4.1: 40x40 minimum touch target on colour screens; 32 on the
    // 240x240 square, which has no room for 40 px rows and a keyboard.
    if (!s_m.mono) {
        const lv_coord_t min_touch = (s_m.tier == MW_TIER_SMALL) ? 32 : 40;
        if (s_m.row_h < min_touch) s_m.row_h = min_touch;
        if (s_m.btn_h < min_touch) s_m.btn_h = min_touch;
    }

    // Keyboard header buttons and candidates share the row height.
    s_m.bar_h  = s_m.row_h;
    s_m.cand_h = s_m.bar_h;

    // 6x5 key hint: full inner width split in six, height capped by what is
    // left under the header, the typed line and the candidates.
    lv_coord_t inner_w = (lv_coord_t)(s_m.w - 2 * s_m.pad);
    if (inner_w < s_m.kb_cols) inner_w = s_m.kb_cols;
    s_m.kb_key_w = (lv_coord_t)(inner_w / s_m.kb_cols);
    const lv_coord_t chrome = (lv_coord_t)(s_m.bar_h +
                                           lv_font_get_line_height(s_m.font_mono) +
                                           s_m.cand_rows * (s_m.cand_h + s_m.gap) +
                                           2 * s_m.pad + 4 * s_m.gap);
    lv_coord_t kh = (lv_coord_t)((s_m.h - chrome) / s_m.kb_rows);
    if (kh > s_m.kb_key_w) kh = s_m.kb_key_w;
    if (kh < 6) kh = 6;
    s_m.kb_key_h = kh;
}

static void build_styles(void) {
    lv_style_init(&s_st_page);
    lv_style_set_bg_color(&s_st_page, s_p.bg);
    lv_style_set_bg_opa(&s_st_page, LV_OPA_COVER);
    lv_style_set_text_color(&s_st_page, s_p.text);
    lv_style_set_text_font(&s_st_page, s_m.font_body);
    lv_style_set_pad_all(&s_st_page, 0);
    lv_style_set_border_width(&s_st_page, 0);
    lv_style_set_radius(&s_st_page, 0);

    lv_style_init(&s_st_card);
    lv_style_set_bg_color(&s_st_card, s_p.surface);
    lv_style_set_bg_opa(&s_st_card, LV_OPA_COVER);
    lv_style_set_border_color(&s_st_card, s_p.border);
    lv_style_set_border_width(&s_st_card, s_m.mono ? 1 : 0);
    lv_style_set_radius(&s_st_card, s_m.mono ? 0 : 6);
    lv_style_set_pad_all(&s_st_card, s_m.pad);
    lv_style_set_text_color(&s_st_card, s_p.text);

    lv_style_init(&s_st_title);
    lv_style_set_text_font(&s_st_title, s_m.font_title);
    lv_style_set_text_color(&s_st_title, s_p.text);

    lv_style_init(&s_st_dim);
    lv_style_set_text_font(&s_st_dim, s_m.font_small);
    lv_style_set_text_color(&s_st_dim, s_p.text_dim);

    lv_style_init(&s_st_mono);
    lv_style_set_text_font(&s_st_mono, s_m.font_mono);
    lv_style_set_text_color(&s_st_mono, s_p.text);

    lv_style_init(&s_st_key);
    lv_style_set_bg_color(&s_st_key, s_p.surface);
    lv_style_set_bg_opa(&s_st_key, LV_OPA_COVER);
    lv_style_set_text_color(&s_st_key, s_p.text);
    lv_style_set_text_font(&s_st_key, s_m.font_body);
    lv_style_set_radius(&s_st_key, s_m.mono ? 0 : 4);
    // A 1 px edge on every key cap: adjacent caps used to merge into one
    // grey slab (task2 item 14).
    lv_style_set_border_width(&s_st_key, 1);
    lv_style_set_border_color(&s_st_key, s_p.border);
    lv_style_set_pad_all(&s_st_key, 0);

    lv_style_init(&s_st_key_dead);
    // Dead keys: clearly dimmer than live ones, but still legible.
    lv_style_set_text_color(&s_st_key_dead, lv_color_hex(0x707078));
    lv_style_set_bg_color(&s_st_key_dead, s_p.bg);
    lv_style_set_border_color(&s_st_key_dead, lv_color_hex(0x3A3A42));

    // Focus styling.
    //
    // Mono panels: invert the focused object (white bg, black text).
    // Colour panels: fill the whole object with the accent colour and
    // switch the text to a contrasting one.
    lv_style_init(&s_st_focus);
    if (s_p.focus_invert) {
        lv_style_set_bg_color(&s_st_focus, s_p.focus_bg);
        lv_style_set_bg_opa(&s_st_focus, LV_OPA_COVER);
        lv_style_set_text_color(&s_st_focus, s_p.focus_text);
        lv_style_set_outline_width(&s_st_focus, 0);
    } else {
        lv_style_set_bg_color(&s_st_focus, s_p.focus_bg);
        lv_style_set_bg_opa(&s_st_focus, LV_OPA_COVER);
        lv_style_set_text_color(&s_st_focus, s_p.focus_text);
        lv_style_set_outline_width(&s_st_focus, 0);
    }

    // Seed word highlight: the first fully visible row of the seed list.
    // On colour panels it is a solid accent block with white text; on
    // monochrome panels it is inverted (white background, black text).
    lv_style_init(&s_st_seed_current);
    if (s_m.mono) {
        lv_style_set_bg_color(&s_st_seed_current, lv_color_white());
        lv_style_set_bg_opa(&s_st_seed_current, LV_OPA_COVER);
        lv_style_set_text_color(&s_st_seed_current, lv_color_black());
    } else {
        lv_style_set_bg_color(&s_st_seed_current, s_p.accent);
        lv_style_set_bg_opa(&s_st_seed_current, LV_OPA_COVER);
        lv_style_set_text_color(&s_st_seed_current, lv_color_white());
    }
    lv_style_set_pad_all(&s_st_seed_current, 1);
    lv_style_set_radius(&s_st_seed_current, 2);
}

// ---------------------------------------------------------------------------
void mw_theme_init(mw_lv_disp_t* disp) {
    const mw_hal_caps_t* caps = mw_hal_caps();
    build_palette(caps->monochrome);
    build_metrics(caps);
    build_styles();
    s_ready = true;

#if LV_USE_THEME_DEFAULT
    lv_theme_t* th = lv_theme_default_init(disp, s_p.accent, s_p.surface2,
                                           true /* dark */, s_m.font_body);
    if (th) MW_DISP_SET_THEME(disp, th);
#else
    MW_UNUSED(disp);
#endif
}

const mw_metrics_t* mw_metrics(void) { return &s_m; }
const mw_palette_t* mw_palette(void) { return &s_p; }

lv_style_t* mw_style_page(void)     { return &s_st_page; }
lv_style_t* mw_style_card(void)     { return &s_st_card; }
lv_style_t* mw_style_title(void)    { return &s_st_title; }
lv_style_t* mw_style_dim(void)      { return &s_st_dim; }
lv_style_t* mw_style_mono(void)     { return &s_st_mono; }
lv_style_t* mw_style_key(void)      { return &s_st_key; }
lv_style_t* mw_style_key_dead(void) { return &s_st_key_dead; }
lv_style_t* mw_style_focus(void)    { return &s_st_focus; }
lv_style_t* mw_style_seed_current(void) { return &s_st_seed_current; }

void mw_theme_button(lv_obj_t* btn) {
    if (!btn) return;
    lv_obj_set_style_bg_color(btn, s_p.surface, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_bg_color(btn, s_p.surface2, LV_PART_MAIN | LV_STATE_PRESSED);
    lv_obj_set_style_text_color(btn, s_p.text, LV_PART_MAIN);
    lv_obj_set_style_text_font(btn, s_m.font_body, LV_PART_MAIN);
    lv_obj_set_style_radius(btn, s_m.mono ? 0 : 6, LV_PART_MAIN);
    // Buttons carry a visible edge on colour panels too (task2 item 14).
    lv_obj_set_style_border_width(btn, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(btn, s_p.border, LV_PART_MAIN);
    lv_obj_set_style_min_height(btn, s_m.btn_h, LV_PART_MAIN);
    if (!s_m.mono) lv_obj_set_style_min_width(btn, 40, LV_PART_MAIN);
    lv_obj_add_style(btn, &s_st_focus, LV_PART_MAIN | LV_STATE_FOCUSED);
}

void mw_theme_button_fixed(lv_obj_t* btn, lv_coord_t w, lv_coord_t h) {
    if (!btn) return;
    mw_theme_button(btn);
    lv_obj_set_style_pad_all(btn, 0, LV_PART_MAIN);
    lv_obj_set_style_min_height(btn, 0, LV_PART_MAIN);
    lv_obj_set_style_min_width(btn, 0, LV_PART_MAIN);
    lv_obj_set_size(btn, w, h);
}

void mw_theme_danger_button(lv_obj_t* btn) {
    if (!btn) return;
    mw_theme_button(btn);
    lv_obj_set_style_bg_color(btn, s_p.danger, LV_PART_MAIN);
    lv_obj_set_style_text_color(btn, lv_color_white(), LV_PART_MAIN);
}
const lv_font_t* mw_font_seed_word(void) {
    const mw_metrics_t* m = mw_metrics();
    int want;
    switch (m->tier) {
    case MW_TIER_TINY:    want = 12; break;
    case MW_TIER_SMALL:   want = 12; break;
    case MW_TIER_MEDIUM:  want = 14; break;
    case MW_TIER_LARGE:   want = 20; break;
    case MW_TIER_XLARGE:
    default:              want = 28; break;
    }
    if (want > 14 && m->tier <= MW_TIER_MEDIUM) want = 14;
    return mw_font_montserrat(want);
}
