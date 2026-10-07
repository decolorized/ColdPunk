// Six-button navigation and the optional quadrature encoder (TZ 2.5, 5.6).
//
// Wiring assumption: every button is a momentary switch to GND read through
// the ESP32-S3 internal pull-up, so "pressed" is a logic low.  Set
// BUTTON_ACTIVE_LOW to 0 in board_config.h for a board that pulls up instead.
//
// Debounce: a raw level must hold for MW_BTN_DEBOUNCE_MS (20 ms) before it is
// accepted.  That is long enough for the tactile domes used on these boards
// and still far inside the 100 ms input-latency budget of TZ 4.1.
//
// Press length (TZ 5.6): the HAL reports raw hold time only.  mw_buttons_read()
// returns the pressed set (one bit per mw_button_t) and mw_buttons_press_ms()
// how long one button has been down; the thresholds that turn a hold into
// "clear the prefix" or "clear the phrase" belong to the UI, which applies
// MW_BACK_LONG_MS / MW_BACK_VERY_LONG_MS from src/ui/screen_common.h.
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include "display_drivers.h"

// ===========================================================================
// Buttons
// ===========================================================================
#define MW_BTN_COUNT 7   // index 0 is MW_BTN_NONE and is never used

// Indexed by mw_button_t so the bit index and the enum value coincide.
static const int8_t s_pins[MW_BTN_COUNT] = {
    -1,                 // MW_BTN_NONE
    (int8_t)BUTTON_UP,
    (int8_t)BUTTON_DOWN,
    (int8_t)BUTTON_LEFT,
    (int8_t)BUTTON_RIGHT,
    (int8_t)BUTTON_SELECT,
    (int8_t)BUTTON_BACK
};

typedef struct {
    bool     raw;          // last sampled level, already polarity-corrected
    bool     stable;       // level that survived the debounce window
    uint32_t changed_ms;   // when `raw` last differed from `stable`
    uint32_t pressed_ms;   // when `stable` went true
} mw_btn_state_t;

static mw_btn_state_t s_btn[MW_BTN_COUNT];
static bool           s_btn_ready = false;

static inline bool btn_level(int8_t pin)
{
    int v = digitalRead(pin);
#if BUTTON_ACTIVE_LOW
    return v == LOW;
#else
    return v == HIGH;
#endif
}

void mw_buttons_poll(void)
{
    if (!s_btn_ready) return;
    const uint32_t now = millis();

    for (int i = 1; i < MW_BTN_COUNT; ++i) {
        if (s_pins[i] < 0) continue;
        mw_btn_state_t* b = &s_btn[i];

        bool lvl = btn_level(s_pins[i]);
        if (lvl != b->raw) {            // bouncing: restart the window
            b->raw        = lvl;
            b->changed_ms = now;
            continue;
        }
        if (lvl == b->stable) continue; // nothing new

        if ((uint32_t)(now - b->changed_ms) >= MW_BTN_DEBOUNCE_MS) {
            b->stable = lvl;
            if (lvl) b->pressed_ms = now;
        }
    }
}

uint32_t mw_buttons_press_ms(mw_button_t btn)
{
    int i = (int)btn;
    if (i <= 0 || i >= MW_BTN_COUNT) return 0;
    if (!s_btn_ready || !s_btn[i].stable) return 0;
    return (uint32_t)(millis() - s_btn[i].pressed_ms);
}

uint32_t mw_buttons_read(void)
{
    if (!s_btn_ready) return 0;
    mw_buttons_poll();

    uint32_t mask = 0;

    for (int i = 1; i < MW_BTN_COUNT; ++i) {
        if (s_pins[i] < 0 || !s_btn[i].stable) continue;
        mask |= 1u << i;
    }
    return mask;
}

// ===========================================================================
// Encoder (optional; replaces Left/Right per TZ 2.5)
// ===========================================================================
#if (BUTTON_ENCODER_A >= 0) && (BUTTON_ENCODER_B >= 0)
#define MW_HAS_ENCODER 1
#else
#define MW_HAS_ENCODER 0
#endif

#if MW_HAS_ENCODER

// Most detented encoders run through a full Gray cycle between detents, i.e.
// four transitions.  Override in board_config.h for a non-detented wheel.
#ifndef ENCODER_COUNTS_PER_DETENT
#define ENCODER_COUNTS_PER_DETENT 4
#endif

// Transition table indexed by (previous << 2) | current, where each 2-bit
// half is (A << 1) | B.  Illegal transitions (both lines moving at once) map
// to 0, which is what makes this immune to contact bounce: a bounce walks
// back and forth between two adjacent states and nets out to zero.
static const int8_t s_qtab[16] = {
     0, -1,  1,  0,
     1,  0,  0, -1,
    -1,  0,  0,  1,
     0,  1, -1,  0
};

static volatile int32_t s_enc_counts = 0;
static volatile uint8_t s_enc_prev   = 0;

static void IRAM_ATTR enc_isr(void)
{
    uint8_t cur = (uint8_t)((digitalRead(BUTTON_ENCODER_A) << 1) |
                             digitalRead(BUTTON_ENCODER_B));
    s_enc_counts += s_qtab[((s_enc_prev & 0x03) << 2) | cur];
    s_enc_prev    = cur;
}
#endif  // MW_HAS_ENCODER

int32_t mw_encoder_read(void)
{
#if MW_HAS_ENCODER
    // Read-and-subtract rather than read-and-zero: a pulse that lands between
    // the two statements is kept instead of being dropped.
    noInterrupts();
    int32_t raw = s_enc_counts;
    int32_t detents = raw / ENCODER_COUNTS_PER_DETENT;
    s_enc_counts = raw - detents * ENCODER_COUNTS_PER_DETENT;
    interrupts();
    return detents;
#else
    return 0;
#endif
}

// ===========================================================================
// Init
// ===========================================================================
mw_err_t mw_buttons_init(void)
{
#if !HAS_BUTTONS && !MW_HAS_ENCODER
    return MW_ERR_NOT_SUPPORTED;        // touch-only board
#else
    const uint32_t now = millis();
    int configured = 0;

    for (int i = 1; i < MW_BTN_COUNT; ++i) {
        s_btn[i].raw        = false;
        s_btn[i].stable     = false;
        s_btn[i].changed_ms = now;
        s_btn[i].pressed_ms = now;
        if (s_pins[i] < 0) continue;
#if BUTTON_ACTIVE_LOW
        pinMode(s_pins[i], INPUT_PULLUP);
#else
        pinMode(s_pins[i], INPUT_PULLDOWN);
#endif
        ++configured;
    }
    s_btn_ready = true;

#if MW_HAS_ENCODER
#if BUTTON_ACTIVE_LOW
    pinMode(BUTTON_ENCODER_A, INPUT_PULLUP);
    pinMode(BUTTON_ENCODER_B, INPUT_PULLUP);
#else
    pinMode(BUTTON_ENCODER_A, INPUT);
    pinMode(BUTTON_ENCODER_B, INPUT);
#endif
    s_enc_prev   = (uint8_t)((digitalRead(BUTTON_ENCODER_A) << 1) |
                              digitalRead(BUTTON_ENCODER_B));
    s_enc_counts = 0;
    attachInterrupt(digitalPinToInterrupt(BUTTON_ENCODER_A), enc_isr, CHANGE);
    attachInterrupt(digitalPinToInterrupt(BUTTON_ENCODER_B), enc_isr, CHANGE);
    ++configured;
#endif

    // A board that claims HAS_BUTTONS but wired none of them is a config bug
    // worth catching at boot rather than at the first seed-entry screen.
    return (configured > 0) ? MW_OK : MW_ERR_INVALID_ARG;
#endif
}

#endif  // ARDUINO && !MW_HOST_BUILD
