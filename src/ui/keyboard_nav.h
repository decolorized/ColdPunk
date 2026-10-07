// ---------------------------------------------------------------------------
//  Button navigation of the on-screen keyboards for boards with 4..6 buttons
//  (user request, v6). Platform independent: the press/hold/release logic and
//  the cursor stepping live here so the host tests can drive them; the two
//  keyboard layouts (keyboard_full.cpp, keyboard_scroll.cpp) only map the
//  resulting actions onto their widgets.
//
//  Buttons inside a keyboard
//    SELECT short (released before MW_KN_LONG_MS)  type the focused character
//                                                  (or act on the focused key)
//    SELECT long  (held MW_KN_LONG_MS)             finish the input (OK)
//    BACK   short                                  delete one character
//    BACK   long                                   leave the input (cancel /
//                                                  back to the previous step)
//    arrow        one step at once; held: repeats after MW_KN_REPEAT_DELAY_MS
//                 every MW_KN_REPEAT_MS (like a PC keyboard)
//    two arrows at once                            switch the layout (the same
//                 as the on-screen layout key, which stays); the step the
//                 first arrow already made is undone
//
//  Four-button boards (no LEFT/RIGHT wired): UP / DOWN walk through every
//  focusable item in reading order and wrap around - the header [Back], the
//  candidates, then the keys.
//
//  Seed input: keys of letters that cannot continue any word are skipped by
//  every move, so a word needs fewer presses.
//
// SPDX-License-Identifier: MIT
// ---------------------------------------------------------------------------
#ifndef MW_UI_KEYBOARD_NAV_H
#define MW_UI_KEYBOARD_NAV_H

#include <stdbool.h>
#include <stdint.h>

#include "../hal/hal.h"     // mw_button_t

#ifdef __cplusplus
extern "C" {
#endif

#define MW_KN_LONG_MS          600   // = MW_BACK_LONG_MS
#define MW_KN_REPEAT_DELAY_MS  500
#define MW_KN_REPEAT_MS        120
// A second arrow pressed within this time after the first one is a chord
// (layout switch) and the first arrow's step is taken back.
#define MW_KN_CHORD_MS         350

typedef enum {
    MW_KN_NONE = 0,
    MW_KN_MOVE,        // .dir = the arrow
    MW_KN_ACTIVATE,    // short SELECT
    MW_KN_FINISH,      // long SELECT
    MW_KN_BACKSPACE,   // short BACK
    MW_KN_CANCEL,      // long BACK
    MW_KN_LAYOUT       // two arrows at once
} mw_kn_action_t;

typedef struct {
    mw_kn_action_t act;
    mw_button_t    dir;          // MW_KN_MOVE
    bool           undo_move;    // MW_KN_LAYOUT: revert the last MW_KN_MOVE
} mw_kn_out_t;

typedef struct {
    uint32_t held;               // bit per mw_button_t
    uint32_t consumed;           // release of these does nothing
    uint32_t press_ms[8];
    uint32_t repeat_ms[8];
    uint32_t moves[8];           // steps made by the current press of an arrow
    bool     long_fired[8];
} mw_kn_t;

void        mw_kn_reset(mw_kn_t* k);
// One event from the UI button hook: press edge (hold_ms 0, !released), held
// (hold_ms > 0), release. `now_ms` is the current time.
mw_kn_out_t mw_kn_event(mw_kn_t* k, mw_button_t b, uint32_t hold_ms, bool released,
                        uint32_t now_ms);

// ---- cursor stepping ------------------------------------------------------
// live(i) says whether item i may take the focus (a dead seed letter may not).
typedef bool (*mw_kn_live_fn)(int index, void* ctx);

// Linear walk with wrap-around over `count` items: the next live item after
// (dir > 0) or before (dir < 0) `cur`. Returns `cur` when nothing else is
// live; -1 when count is 0.
int mw_kn_linear_step(int count, int cur, int dir, mw_kn_live_fn live, void* ctx);

// Grid of `n` cells, `cols` per row (row-major, last row may be short).
//   LEFT / RIGHT  previous / next live cell, crossing row ends, no wrap
//   UP / DOWN     the cell above / below; if it is dead, the nearest live cell
//                 of that row; if the row has none, the row after that
// Returns the new index, or -1 when UP leaves the top row (the caller moves
// the focus to the candidates / header). At the other edges the cursor stays.
int mw_kn_grid_step(int n, int cols, int cur, mw_button_t dir,
                    mw_kn_live_fn live, void* ctx);

#ifdef __cplusplus
}
#endif
#endif
