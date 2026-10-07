// ---------------------------------------------------------------------------
//  Minesweeper model (task 3 item 7, bug v5 #1). Pure C, no LVGL, so the
//  rules, the input state machine and the layout are host-tested
//  (test/test_game.c). screen_game.cpp is only the LVGL view.
// ---------------------------------------------------------------------------
#ifndef MW_UI_GAME_MODEL_H
#define MW_UI_GAME_MODEL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MW_GAME_MAX_COLS          10
#define MW_GAME_MAX_ROWS          12
#define MW_GAME_MAX_CELLS         (MW_GAME_MAX_COLS * MW_GAME_MAX_ROWS)
#define MW_GAME_MIN_COLS          6
#define MW_GAME_MIN_ROWS          4
#define MW_GAME_CELL_MIN_TOUCH    32      // px, floor for finger-sized cells
#define MW_GAME_CELL_MIN_KEYS     16      // px, button-only boards
#define MW_GAME_UNLOCK_TAPS       3
#define MW_GAME_UNLOCK_WINDOW_MS  2000u
// Room for the lv_buttonmatrix map: cells + row breaks + the "" terminator.
#define MW_GAME_MAP_LEN           (MW_GAME_MAX_CELLS + MW_GAME_MAX_ROWS + 1)

typedef enum { MW_GAME_PLAY = 0, MW_GAME_LOST, MW_GAME_WON } mw_game_state_t;

// What the view has to do after an input event.
typedef enum {
    MW_GAME_IN_NONE = 0,    // nothing changed
    MW_GAME_IN_PAINT,       // repaint the board
    MW_GAME_IN_UNLOCK,      // the unlock gesture completed: leave the game
} mw_game_input_t;

typedef struct {
    int             cols, rows, cells, mines;
    bool            mine[MW_GAME_MAX_CELLS];
    bool            open[MW_GAME_MAX_CELLS];
    bool            flag[MW_GAME_MAX_CELLS];
    uint8_t         adj[MW_GAME_MAX_CELLS];
    bool            placed;          // mines are laid on the first reveal
    mw_game_state_t state;
    int             exploded;        // cell index of the mine that went off
    int             taps;            // unlock taps counted so far
    uint32_t        first_tap_ms;
    bool            flag_mode;       // taps flag instead of reveal
    int             long_pressed;    // cell whose release must be swallowed, -1
} mw_game_t;

// Smallest cell side for a board: finger-sized on touch panels (follows the
// theme's button height), smaller on button-only boards.
int  mw_game_cell_min(bool touch, int btn_h);

// Board geometry for a free area of avail_w x avail_h pixels. Cells are
// square and at least cell_min where the area allows. The result always fits:
// (*cols) * (*cell) <= avail_w and (*rows) * (*cell) <= avail_h, cell >= 1.
void mw_game_layout(int avail_w, int avail_h, int cell_min,
                    int* cols, int* rows, int* cell);

// Empty board; mines = 15 % of the cells (at least 4), laid on first reveal.
void mw_game_init(mw_game_t* g, int cols, int rows);

// Reveal / flag in MW_GAME_PLAY. The first reveal places the mines from
// mw_random_bytes() and keeps that cell's 3x3 neighbourhood clear.
void mw_game_reveal(mw_game_t* g, int i);
void mw_game_toggle_flag(mw_game_t* g, int i);
int  mw_game_flags(const mw_game_t* g);

// The way into the wallet: after a loss, MW_GAME_UNLOCK_TAPS taps on the
// exploded cell, all within MW_GAME_UNLOCK_WINDOW_MS of the first one.
// Returns true on the tap that completes the gesture. Any tap elsewhere, or
// mw_game_unlock_reset() (a long press), restarts the count.
bool mw_game_unlock_tap(mw_game_t* g, int i, uint32_t now_ms);
void mw_game_unlock_reset(mw_game_t* g);

// Input state machine, fed by the view:
//  on_press      - finger/SELECT down: clears the long-press mark (a hold
//                  that slid off its cell sends no release).
//  on_long_press - flags a closed cell in PLAY; in LOST restarts the unlock
//                  count (a hold is never a tap). Marks the cell so its
//                  release is swallowed once.
//  on_release    - a tap: unlock tap in LOST, flag or reveal in PLAY.
mw_game_input_t mw_game_on_press(mw_game_t* g);
mw_game_input_t mw_game_on_long_press(mw_game_t* g, int i);
mw_game_input_t mw_game_on_release(mw_game_t* g, int i, uint32_t now_ms);

// Keypad navigation: the cell dc columns / dr rows away from i, clamped to
// the board.
int mw_game_move(const mw_game_t* g, int i, int dc, int dr);

// What a cell shows, NEVER an empty string: lv_buttonmatrix ends its map at
// the first "" (bug v5 #1: the board had zero buttons).
const char* mw_game_cell_text(const mw_game_t* g, int i, char out[4]);
bool        mw_game_cell_shown(const mw_game_t* g, int i);   // drawn "opened"

// Fills text[] and map[] for lv_buttonmatrix_set_map(); returns the number
// of buttons LVGL will count in the map (must equal g->cells), -1 if map_len
// is too small.
int mw_game_build_map(const mw_game_t* g, char text[][4], const char* map[], size_t map_len);

#ifdef __cplusplus
}
#endif
#endif
