// ---------------------------------------------------------------------------
//  Shared internals of the two on-screen keyboards (TZ 5.4).
//
//  keyboard_full.cpp holds mw_kb_run(), the model that both layouts share and
//  the type-1 "full keyboard" layout; keyboard_scroll.cpp holds the type-2
//  "scroll keyboard" layout. Both layouts drive exactly the same model and
//  both work under touch AND the six-button navigation of TZ 5.6.
//
//  BUTTON SEMANTICS (TZ 5.6):
//    Back, hold          - backspace with auto-repeat: one character now, then
//                          every MW_ARROW_REPEAT_INTERVAL_MS after
//                          MW_ARROW_REPEAT_DELAY_MS until released;
//    arrow keys, hold    - one step immediately, then repeat every
//                          MW_ARROW_REPEAT_INTERVAL_MS after
//                          MW_ARROW_REPEAT_DELAY_MS until released;
//    SELECT, short       - act on the focused cell on release (letter,
//                          candidate, ⌫ / Space / ↵, or [Back] in the header);
//    SELECT, hold        - the moment hold_ms reaches MW_BACK_LONG_MS, finish
//                          the input (MW_KB_R_OK) right away. Nothing is
//                          typed on the press edge, so a long press cannot
//                          emit a spurious character before finishing.
//
//  A [Back] button is present in the header on every layout and every tier,
//  including the 128x64 scroll keyboard. Up from the top row focuses it, and
//  Select on it leaves the keyboard with MW_KB_R_CANCEL.
// ---------------------------------------------------------------------------
#ifndef MW_UI_KEYBOARD_H
#define MW_UI_KEYBOARD_H

#include "screen_common.h"
#include "../data/wordlist.h"

#ifdef __cplusplus
extern "C" {
#endif

// TZ 5.9 demands an arbitrary-length passphrase. The practical ceiling is the
// session scratch buffer the passphrase screen types into, so the keyboard
// buffer matches it exactly - anything smaller would silently truncate a long
// diceware passphrase and leave the user with a wallet they cannot reproduce
// from what they wrote down. Keep this equal to MW_PASSPHRASE_MAX
// (screen_common.h) and to MW_SESSION_INPUT_CAP (session.c).
#define MW_KB_TEXT_MAX    256   // free-text (passphrase) buffer, TZ 5.9
#define MW_KB_PREFIX_MAX   24
#define MW_KB_MAX_CAND     16
#define MW_KB_GRID_CELLS   30   // 6 x 5, exactly as in the TZ 5.4 mock-ups
#define MW_KB_LETTERS      26
// TZ 4.1: minimum touch target on a colour panel, applied to key caps.
#define MW_KB_MIN_KEY_PX   40

// Auto-repeat for Back and the arrow keys (TZ 5.6).
//   * the first press acts immediately;
//   * the next action only happens after MW_ARROW_REPEAT_DELAY_MS;
//   * after that, actions repeat every MW_ARROW_REPEAT_INTERVAL_MS until the
//     key is released.
#define MW_ARROW_REPEAT_DELAY_MS     500
#define MW_ARROW_REPEAT_INTERVAL_MS  120

// Result codes handed to mw_kb_finish().
enum {
    MW_KB_R_OK      = 1,
    MW_KB_R_CANCEL  = 0,
    MW_KB_R_BACK    = 2,
    MW_KB_R_RESTART = 3
};

// Cells 26..29 of the grid. The meaning of cell 27 depends on the mode, which
// is exactly what the two TZ mock-ups show ([⌨] on the touch mock-up,
// [↵] on the 128x64 one).
enum {
    MW_KC_NONE = 0,
    MW_KC_BKSP,      // backspace
    MW_KC_ACCEPT,    // dictionary mode: take the first candidate
    MW_KC_LAYER,     // free-text mode: cycle lower/UPPER/12#/sym
    MW_KC_PREV,      // dictionary: page candidates left / previous word
    MW_KC_NEXT,      // dictionary: page candidates right
    MW_KC_SPACE,
    MW_KC_ENTER
};

typedef enum {
    MW_KB_LAYER_LOWER = 0,
    MW_KB_LAYER_UPPER,
    MW_KB_LAYER_SYM1,
    MW_KB_LAYER_SYM2,
    MW_KB_LAYER_COUNT
} mw_kb_layer_t;

// Which part of the screen the button cursor is on.
typedef enum {
    MW_KB_AREA_CAND = 0,
    MW_KB_AREA_KEYS,
    MW_KB_AREA_FOOTER,
    MW_KB_AREA_HEADER    // [Back] in the header
} mw_kb_area_t;

typedef struct mw_kb_state mw_kb_state_t;

struct mw_kb_state {
    mw_kb_ctx_t          ctx;
    const mw_wordlist_t* wl;              // NULL in MW_KB_MODE_FREE_TEXT

    // --- model ---
    char                 prefix[MW_KB_PREFIX_MAX];   // dictionary mode
    uint8_t              prefix_len;
    char                 text[MW_KB_TEXT_MAX];       // free-text mode
    uint16_t             text_len;
    uint16_t             cand[MW_KB_MAX_CAND];
    int                  cand_n;          // shown on this page
    int                  cand_avail;      // matches actually returned (<= 16)
    int                  cand_total;      // total matches in the dictionary
    int                  cand_page;
    bool                 at_limit;        // last key refused: buffer is full
    uint32_t             next_mask;       // 26-bit, 'a' = bit 0
    mw_kb_layer_t        layer;
    uint32_t             last_activity_ms;

    // --- view ---
    mw_page_t            page;
    lv_obj_t*            lbl_word;
    lv_obj_t*            lbl_prefix;
    lv_obj_t*            cand_cont;
    lv_obj_t*            cand_btn[MW_KB_MAX_CAND];
    int                  cand_slots;
    lv_obj_t*            keys_cont;
    lv_obj_t*            btn_back;        // [Back] in the header

    // full keyboard: 30 cells; scroll keyboard: 26 letters + 4 specials
    lv_obj_t*            key_btn[MW_KB_GRID_CELLS];
    lv_obj_t*            key_lbl[MW_KB_GRID_CELLS];
    char                 key_ch[MW_KB_GRID_CELLS];    // 0 for special cells
    uint8_t              key_cmd[MW_KB_GRID_CELLS];   // MW_KC_*
    int                  key_n;
    // Grid shape of the full keyboard: ABC 6x5 (8x4 in landscape), QWERTY
    // 10x3. Filled by mw_kb_fill_cells().
    uint8_t              cols, rows;
    bool                 qwerty;

    lv_obj_t*            strip;           // scroll keyboard letter strip
    lv_timer_t*          timeout_timer;

    // --- button cursor (TZ 5.6) ---
    mw_kb_area_t         area;
    int                  cur_row, cur_col;

    // --- auto-repeat for Back and the arrow keys ---
    mw_button_t          repeat_btn;      // currently held button (0 = none)
    uint32_t             repeat_next_ms;  // when the next repeat is allowed
    bool                 select_hold_fired; // true once the long SELECT fired

    // --- output ---
    char*                out;
    size_t               out_cap;
};

// ---- model, implemented in keyboard_full.cpp ------------------------------
bool  mw_kb_is_dict(const mw_kb_state_t* st);
void  mw_kb_refresh(mw_kb_state_t* st);
void  mw_kb_input_char(mw_kb_state_t* st, char c);
void  mw_kb_backspace(mw_kb_state_t* st);
void  mw_kb_clear_prefix(mw_kb_state_t* st);
void  mw_kb_clear_all(mw_kb_state_t* st);
void  mw_kb_accept_candidate(mw_kb_state_t* st, int idx);
void  mw_kb_finish(mw_kb_state_t* st, int result);
bool  mw_kb_letter_live(const mw_kb_state_t* st, char c);
void  mw_kb_touch_activity(mw_kb_state_t* st);
const char* mw_kb_layer_chars(mw_kb_layer_t layer);

// ---- shared view pieces, implemented in keyboard_full.cpp -----------------
void  mw_kb_build_frame(mw_kb_state_t* st);
void  mw_kb_update_header(mw_kb_state_t* st);
void  mw_kb_update_candidates(mw_kb_state_t* st);
lv_obj_t* mw_kb_make_key(mw_kb_state_t* st, lv_obj_t* parent, int cell,
                         lv_coord_t w, lv_coord_t h);
void  mw_kb_key_label(mw_kb_state_t* st, int cell, char* buf, size_t cap);
void  mw_kb_cell_activate(mw_kb_state_t* st, int cell);
void  mw_kb_fill_cells(mw_kb_state_t* st);
void  mw_kb_paint_cells(mw_kb_state_t* st);
void  mw_kb_focus(mw_kb_state_t* st, lv_obj_t* obj);

// ---- layout hooks --------------------------------------------------------
void mw_kb_full_build(mw_kb_state_t* st);
void mw_kb_full_update(mw_kb_state_t* st);
bool mw_kb_full_button(mw_kb_state_t* st, mw_button_t b, uint32_t hold_ms,
                       bool released);

void mw_kb_scroll_build(mw_kb_state_t* st);
void mw_kb_scroll_update(mw_kb_state_t* st);
bool mw_kb_scroll_button(mw_kb_state_t* st, mw_button_t b, uint32_t hold_ms,
                         bool released);

#ifdef __cplusplus
}
#endif
#endif