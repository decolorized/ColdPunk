// ---------------------------------------------------------------------------
//  Seed screens (TZ 4.2, 6.4, 6.5):
//    * dice entropy input  - 100 d6 throws ~ 258 bits;
//    * seed display        - one focusable list, for writing down on paper;
//    * seed verification   - a few random words typed back on the keyboard.
//
//  Dice screen                          Seed display
//  ┌────────────────────────────┐   ┌────────────────────────────┐
//  │ Кубики (d6)                │   │ Слова 1-25 из 25           │
//  │ Бросков: 37 из 100         │   │  1. abandon                │  ← focused
//  │ ████████░░░░░░░░░░ ~95 бит │   │  2. ability                │
//  │  [1] [2] [3]               │   │  3. able                   │
//  │  [4] [5] [6]               │   │  ...                       │
//  │ [Отменить] [Готово]        │   │ 25. zoo                    │
//  └────────────────────────────┘   │ [ Готово ]                 │  ← last row
//                                   └────────────────────────────┘
//
//  Seed display: the seed list is a plain scrollable menu. Every word is
//  its own row in an lv_list, and [Done] is the last row of the same list.
//  LVGL scrolls an lv_list to the focused row on its own, which is what
//  makes the last rows reachable on a 240x240 panel where only 15 of the
//  25 words fit at once.
//
//  Navigation:
//    * Up / Down    - move the focus between the rows, including [Done];
//    * Select       - on a word: nothing; on [Done]: finish the screen;
//    * Back / ESC   - leave the screen without finishing.
//
//  mw_screen_dice_run() and mw_screen_seed_display_run() are blocking helpers
//  that the crypto task calls; the *_build functions inside run on the LVGL
//  task. mw_screen_seed_verify_run() is pure orchestration - it only calls
//  other blocking helpers - so it runs entirely on the caller's task.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../crypto/random.h"
#include "../crypto/memzero.h"
#include "../config/app_config.h"

#include <stdio.h>
#include <string.h>

// ===========================================================================
//  Dice entropy (TZ 6.4)
// ===========================================================================
typedef struct {
    mw_page_t  page;
    uint8_t*   rolls;
    int        max_rolls;
    int        count;
    lv_obj_t*  bar;
    lv_obj_t*  lbl_count;
    lv_obj_t*  lbl_bits;
    lv_obj_t*  btn_done;
} dice_ctx_t;

static dice_ctx_t s_dice;

static int dice_bits(int rolls) {
    // log2(6) in Q8 fixed point, see MW_DICE_BITS_PER_ROLL_Q8.
    return (rolls * MW_DICE_BITS_PER_ROLL_Q8) >> 8;
}

static void dice_update(dice_ctx_t* c) {
    const int permille = (c->count >= MW_DICE_TARGET_ROLLS)
                             ? 1000
                             : (c->count * 1000) / MW_DICE_TARGET_ROLLS;
    if (c->bar) lv_bar_set_value(c->bar, permille, LV_ANIM_OFF);
    if (c->lbl_count) {
        lv_label_set_text_fmt(c->lbl_count, TX(XSTR_DICE_ROLLS),
                              c->count, MW_DICE_TARGET_ROLLS);
    }
    if (c->lbl_bits) {
        lv_label_set_text_fmt(c->lbl_bits, TX(XSTR_DICE_BITS),
                              dice_bits(c->count));
    }
    if (c->btn_done) {
        if (c->count >= MW_DICE_TARGET_ROLLS) {
            MW_OBJ_CLEAR_STATE(c->btn_done, LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(c->btn_done, LV_STATE_DISABLED);
        }
    }
}

static void dice_finish(int32_t r) {
    mw_ui_page_destroy(&s_dice.page);
    mw_ui_modal_done(r);
}

static void dice_face_cb(lv_event_t* e) {
    const int face = (int)(intptr_t)lv_event_get_user_data(e);   // 1..6
    if (s_dice.count >= s_dice.max_rolls) return;
    s_dice.rolls[s_dice.count++] = (uint8_t)face;
    dice_update(&s_dice);
}

static void dice_undo_cb(lv_event_t* e) {
    MW_UNUSED(e);
    if (s_dice.count > 0) {
        s_dice.rolls[--s_dice.count] = 0;
        dice_update(&s_dice);
    }
}

static void dice_done_cb(lv_event_t* e) {
    MW_UNUSED(e);
    if (s_dice.count < MW_DICE_TARGET_ROLLS) return;
    dice_finish(1);
}

static void dice_cancel_cb(lv_event_t* e) { MW_UNUSED(e); dice_finish(0); }
static void dice_escape(void* user)       { MW_UNUSED(user); dice_finish(0); }

static void dice_build(void* arg) {
    dice_ctx_t* c = (dice_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();

    mw_ui_page_create(&c->page, T(STR_ENTROPY_DICE), true);
    mw_ui_page_set_escape(&c->page, dice_escape, c);

    mw_ui_label(c->page.body, T(STR_DICE_PROMPT), mw_style_dim());
    c->lbl_count = mw_ui_label(c->page.body, "", NULL);
    c->bar       = mw_ui_bar(c->page.body);
    c->lbl_bits  = mw_ui_label(c->page.body, "", mw_style_dim());

    lv_obj_t* grid = lv_obj_create(c->page.body);
    lv_obj_remove_style_all(grid);
    lv_obj_set_width(grid, lv_pct(100));
    lv_obj_set_height(grid, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(grid, LV_FLEX_FLOW_ROW_WRAP);
    lv_obj_set_style_pad_row(grid, m->gap, LV_PART_MAIN);
    lv_obj_set_style_pad_column(grid, m->gap, LV_PART_MAIN);
    lv_obj_set_flex_align(grid, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_START);
    MW_OBJ_CLEAR_FLAG(grid, LV_OBJ_FLAG_SCROLLABLE);

    const int cols = (m->w >= 320) ? 6 : 3;
    const lv_coord_t bw = (lv_coord_t)((m->w - 2 * m->pad - (cols - 1) * m->gap) / cols);

    for (int face = 1; face <= 6; face++) {
        char txt[4];
        snprintf(txt, sizeof(txt), "%d", face);
        lv_obj_t* b = mw_ui_button(grid, txt, dice_face_cb, (void*)(intptr_t)face);
        lv_obj_set_size(b, bw, m->btn_h);
        mw_ui_focus_add(&c->page, b);
        if (face == 1) lv_group_focus_obj(b);
    }

    lv_obj_t* f  = mw_ui_page_footer(&c->page);
    lv_obj_t* bu = mw_ui_button(f, TX(XSTR_DICE_UNDO), dice_undo_cb, NULL);
    lv_obj_t* bd = mw_ui_button(f, T(STR_DONE),        dice_done_cb, NULL);
    lv_obj_t* bc = mw_ui_button(f, T(STR_CANCEL),      dice_cancel_cb, NULL);
    lv_obj_set_flex_grow(bu, 1);
    lv_obj_set_flex_grow(bd, 1);
    lv_obj_set_flex_grow(bc, 1);
    mw_ui_focus_add(&c->page, bu);
    mw_ui_focus_add(&c->page, bd);
    mw_ui_focus_add(&c->page, bc);
    c->btn_done = bd;

    dice_update(c);
}

bool mw_screen_dice_run(uint8_t* rolls, int max_rolls, int* n_out) {
    if (!rolls || max_rolls <= 0) return false;
    memset(&s_dice, 0, sizeof(s_dice));
    s_dice.rolls     = rolls;
    s_dice.max_rolls = max_rolls;

    const bool ok = (mw_ui_modal_call(dice_build, &s_dice) == 1);
    if (n_out) *n_out = ok ? s_dice.count : 0;
    if (!ok) memset(rolls, 0, (size_t)max_rolls);
    return ok;
}

// ===========================================================================
//  Seed display (TZ 6.5 step 5)
// ===========================================================================
typedef struct {
    mw_page_t          page;
    const char* const* words;
    int                n;
} seeddisp_ctx_t;

static seeddisp_ctx_t s_disp;

static void seeddisp_escape(void* user) {
    MW_UNUSED(user);
    mw_ui_page_destroy(&s_disp.page);
    mw_ui_modal_done(0);
}

static void seeddisp_done_cb(lv_event_t* e) {
    MW_UNUSED(e);
    mw_ui_page_destroy(&s_disp.page);
    mw_ui_modal_done(1);
}

static void seeddisp_build(void* arg) {
    seeddisp_ctx_t* c = (seeddisp_ctx_t*)arg;

    mw_ui_page_create(&c->page, T(STR_VERIFY_SEED), false);
    mw_ui_page_set_escape(&c->page, seeddisp_escape, c);

    // A plain lv_list: LVGL scrolls it to the focused row on its own, which
    // is exactly what the menu and the wallet list rely on. The words are
    // ordinary rows, and [Done] is the last row of the same list - it is
    // only visible once the user has scrolled to the end.
    lv_obj_t* list = mw_ui_list(c->page.body);

    const mw_metrics_t* mm = mw_metrics();
    // Слова сид-фразы пользователь переписывает на бумагу и потом сверяет
    // глазами - им нужен шрифт на шаг крупнее обычного mono.
    const lv_font_t* word_font = mw_font_seed_word();

    for (int i = 0; i < c->n; i++) {
        char line[40];
        snprintf(line, sizeof(line), "%2d. %s", i + 1,
                 c->words[i] ? c->words[i] : "");

        lv_obj_t* row = mw_ui_list_row(list, NULL, line, NULL, NULL);
        // A list row is already clickable and focusable; no CLICKED handler
        // on purpose: a stray Select on a word must not leave the screen.
        if (row) {
            mw_ui_focus_add(&c->page, row);
            lv_obj_set_style_text_font(row, word_font, LV_PART_MAIN);
            // На XLARGE слово крупнее body - поднимаем строку под шрифт.
            lv_coord_t rh = mm->row_h;
            if (mm->tier == MW_TIER_XLARGE) rh = (lv_coord_t)(rh + mm->gap);
            lv_obj_set_style_min_height(row, rh, LV_PART_MAIN);
        }
    }

    // [Done] is just the last row of the same list.
    lv_obj_t* done = mw_ui_list_row(list, LV_SYMBOL_OK, T(STR_DONE),
                                    seeddisp_done_cb, NULL);
    if (done) {
        mw_ui_focus_add(&c->page, done);
        lv_obj_set_style_bg_color(done, mw_palette()->accent, LV_PART_MAIN);
        lv_obj_set_style_text_color(done, lv_color_white(), LV_PART_MAIN);
    }

    // Focus the first word, so the user starts at word 1.
    if (c->n > 0) {
        lv_obj_t* first = lv_obj_get_child(list, 0);
        if (first) lv_group_focus_obj(first);
    }
}

bool mw_screen_seed_display_run(const char* const* words, int n) {
    if (!words || n <= 0) return false;

    memset(&s_disp, 0, sizeof(s_disp));
    s_disp.words = words;
    s_disp.n     = n;

    if (mw_ui_modal_call(seeddisp_build, &s_disp) != 1) return false;

    return mw_ui_confirm(T(STR_VERIFY_SEED), TX(XSTR_SEED_WRITTEN_Q),
                         T(STR_CONFIRM), T(STR_CANCEL));
}

// ===========================================================================
//  Seed verification (TZ 6.5 step 7): type a few random words back.
//
//  Runs on the caller's task - it is nothing but a sequence of blocking
//  helpers, so it never touches LVGL itself.
// ===========================================================================
#define MW_VERIFY_WORDS   3
#define MW_VERIFY_RETRIES 3

static void pick_indices(int n, int* out, int want) {
    int got = 0;
    while (got < want) {
        uint8_t r;
        mw_random_bytes(&r, 1);
        const int idx = r % n;
        bool dup = false;
        for (int i = 0; i < got; i++) if (out[i] == idx) { dup = true; break; }
        if (!dup) out[got++] = idx;
    }
    for (int i = 1; i < want; i++) {
        for (int j = i; j > 0 && out[j - 1] > out[j]; j--) {
            const int t = out[j - 1]; out[j - 1] = out[j]; out[j] = t;
        }
    }
}

bool mw_screen_seed_verify_run(const char* const* words, int n,
                               mw_kb_mode_t mode) {
    if (!words || n <= 0) return false;

    int want = MW_VERIFY_WORDS;
    if (want > n) want = n;

    for (int attempt = 0; attempt < MW_VERIFY_RETRIES; attempt++) {
        int idx[MW_VERIFY_WORDS];
        pick_indices(n, idx, want);

        bool all_ok = true;
        for (int k = 0; k < want && all_ok; k++) {
            char typed[32];
            char title[48];
            snprintf(title, sizeof(title), TX(XSTR_VERIFY_PROMPT), idx[k] + 1);

            mw_kb_ctx_t kc;
            memset(&kc, 0, sizeof(kc));
            kc.mode       = mode;
            kc.type       = mw_ui_settings()->keyboard;
            kc.title      = title;
            kc.word_index = idx[k] + 1;
            kc.word_total = n;
            kc.allow_back = false;

            const mw_err_t e = mw_kb_run(&kc, typed, sizeof(typed));
            if (e != MW_OK) { mw_memzero(typed, sizeof(typed)); return false; }

            if (strcmp(typed, words[idx[k]]) != 0) all_ok = false;
            mw_memzero(typed, sizeof(typed));
        }

        if (all_ok) {
            mw_ui_message(T(STR_VERIFY_SEED), TX(XSTR_VERIFY_OK));
            return true;
        }
        mw_ui_message(T(STR_ERR_GENERIC), TX(XSTR_VERIFY_FAIL));
    }
    return false;
}
