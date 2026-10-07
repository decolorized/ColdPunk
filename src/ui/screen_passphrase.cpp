// ---------------------------------------------------------------------------
//  Passphrase entry - TZ 5.2 / 5.9. This is a security requirement, so the
//  rules are spelled out here and the code follows them literally:
//
//   1. The passphrase screen is shown ALWAYS, after every seed entry and
//      before every key derivation. There is no code path that skips it.
//   2. An empty passphrase is legal but needs a distinct "Без passphrase"
//      button AND a second explicit confirmation on top of it.
//   3. A non-empty passphrase is typed TWICE and compared in constant time;
//      a mismatch is reported and the whole entry restarts.
//   4. The buffer is wiped with mw_session_wipe_input() on success, on
//      cancel, on mismatch and on any error - never left behind.
//   5. The passphrase is never written to NVS; it only ever lives in the
//      session scratch buffer and in `out`, which the caller must wipe.
//
//      ┌──────────────────────────────┐
//      │ Passphrase                   │
//      │ Passphrase запрашивается     │
//      │ всегда. Он не сохраняется    │
//      │ на устройстве.               │
//      │  [ Ввести passphrase ]       │
//      │  [ Без passphrase    ]       │
//      │  [ Отмена            ]       │
//      └──────────────────────────────┘
//
//  mw_screen_passphrase_run() runs on the caller's (crypto) task: it is a
//  sequence of blocking helpers and never touches LVGL itself.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../wallet/session.h"
#include "../crypto/memzero.h"

#include <stdio.h>
#include <string.h>

// strnlen() is POSIX and present in newlib, but spelling it out keeps this
// file free of feature-test-macro surprises on other toolchains.
static size_t pp_strnlen(const char* s, size_t cap) {
    size_t i = 0;
    while (i < cap && s[i] != '\0') i++;
    return i;
}

enum { PP_CHOICE_ENTER = 1, PP_CHOICE_NONE = 2, PP_CHOICE_CANCEL = 0 };

typedef struct { mw_page_t page; } pp_ctx_t;
static pp_ctx_t s_pp;

static void pp_finish(int32_t r) {
    mw_ui_page_destroy(&s_pp.page);
    mw_ui_modal_done(r);
}
static void pp_enter_cb(lv_event_t* e)  { MW_UNUSED(e); pp_finish(PP_CHOICE_ENTER); }
static void pp_none_cb(lv_event_t* e)   { MW_UNUSED(e); pp_finish(PP_CHOICE_NONE); }
static void pp_cancel_cb(lv_event_t* e) { MW_UNUSED(e); pp_finish(PP_CHOICE_CANCEL); }
static void pp_escape(void* user)       { MW_UNUSED(user); pp_finish(PP_CHOICE_CANCEL); }

static void pp_build(void* arg) {
    pp_ctx_t* c = (pp_ctx_t*)arg;
    mw_ui_page_create(&c->page, T(STR_PASSPHRASE), true);
    mw_ui_page_set_escape(&c->page, pp_escape, c);

    mw_ui_label(c->page.body, TX(XSTR_PASSPHRASE_HINT), mw_style_dim());

    lv_obj_t* b1 = mw_ui_button(c->page.body, TX(XSTR_PASSPHRASE_ENTER),
                                pp_enter_cb, NULL);
    lv_obj_t* b2 = mw_ui_button(c->page.body, T(STR_PASSPHRASE_NONE),
                                pp_none_cb, NULL);
    lv_obj_t* b3 = mw_ui_button(c->page.body, T(STR_CANCEL),
                                pp_cancel_cb, NULL);
    lv_obj_set_width(b1, lv_pct(100));
    lv_obj_set_width(b2, lv_pct(100));
    lv_obj_set_width(b3, lv_pct(100));

    // The "no passphrase" button is deliberately styled as the exceptional
    // choice, not as the easy default.
    lv_obj_set_style_border_width(b2, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(b2, mw_palette()->warn, LV_PART_MAIN);

    mw_ui_focus_add(&c->page, b1);
    mw_ui_focus_add(&c->page, b2);
    mw_ui_focus_add(&c->page, b3);
    lv_group_focus_obj(b1);
}

// ---------------------------------------------------------------------------
static bool confirm_empty_passphrase(void) {
    // Two separate confirmations, as TZ 5.2 demands: the first explains the
    // consequence, the second makes the user say it again.
    if (!mw_ui_confirm(T(STR_PASSPHRASE_NONE), T(STR_PASSPHRASE_NONE_CONFIRM),
                       T(STR_CONFIRM), T(STR_CANCEL))) {
        return false;
    }
    return mw_ui_confirm(T(STR_PASSPHRASE_NONE), TX(XSTR_PASSPHRASE_EMPTY_Q),
                         TX(XSTR_YES), TX(XSTR_NO));
}

static mw_err_t run_keyboard(const char* title, char* buf, size_t cap) {
    mw_kb_ctx_t kc;
    memset(&kc, 0, sizeof(kc));
    kc.mode       = MW_KB_MODE_FREE_TEXT;
    kc.type       = mw_ui_settings()->keyboard;
    kc.title      = title;
    kc.word_index = 0;
    kc.word_total = 0;
    kc.allow_back = false;
    return mw_kb_run(&kc, buf, cap);
}

// ---------------------------------------------------------------------------
// task 3 item 5: opening a wallet. One entry; empty opens the wallet without
// a passphrase (the "second wallet" of the same seed). Whether a non-empty
// entry is right is checked by the caller against the sealed check value.
// ---------------------------------------------------------------------------
mw_err_t mw_screen_passphrase_open_run(const char* wallet_name, char* out,
                                       size_t out_cap) {
    if (!out || out_cap == 0) return MW_ERR_INVALID_ARG;
    out[0] = '\0';

    size_t sess_cap = 0;
    char*  sess     = mw_session_input_buffer(&sess_cap);
    if (!sess || sess_cap < 2) return MW_ERR_MEMORY;
    if (sess_cap > out_cap) sess_cap = out_cap;

    char title[64];
    snprintf(title, sizeof(title), "%s: %s", wallet_name ? wallet_name : "",
             T(STR_PASSPHRASE));
    mw_session_wipe_input();
    mw_err_t e = run_keyboard(title, sess, sess_cap);
    if (e != MW_OK) {
        mw_session_wipe_input();
        return MW_ERR_ABORTED;
    }
    const size_t l = pp_strnlen(sess, sess_cap);
    memcpy(out, sess, l);
    out[l < out_cap ? l : out_cap - 1] = '\0';
    mw_session_wipe_input();
    return MW_OK;
}

mw_err_t mw_screen_passphrase_run(char* out, size_t out_cap) {
    if (!out || out_cap == 0) return MW_ERR_INVALID_ARG;
    out[0] = '\0';

    size_t sess_cap = 0;
    char*  sess     = mw_session_input_buffer(&sess_cap);
    if (!sess || sess_cap < 2) return MW_ERR_MEMORY;
    if (sess_cap > out_cap) sess_cap = out_cap;

    for (;;) {
        memset(&s_pp, 0, sizeof(s_pp));
        const int32_t choice = mw_ui_modal_call(pp_build, &s_pp);

        if (choice == PP_CHOICE_CANCEL || choice < 0) {
            mw_session_wipe_input();
            return MW_ERR_ABORTED;
        }

        if (choice == PP_CHOICE_NONE) {
            if (!confirm_empty_passphrase()) continue;   // back to the screen
            mw_session_wipe_input();
            out[0] = '\0';
            return MW_OK;                                // explicitly empty
        }

        // ---- first entry, into the session scratch buffer -----------------
        mw_session_wipe_input();
        mw_err_t e = run_keyboard(T(STR_PASSPHRASE), sess, sess_cap);
        if (e != MW_OK) {
            mw_session_wipe_input();
            if (e == MW_ERR_ABORTED) continue;           // back to the screen
            return e;
        }

        // ---- second entry, into a local buffer ---------------------------
        char repeat[MW_PASSPHRASE_MAX];
        memset(repeat, 0, sizeof(repeat));
        size_t rcap = sizeof(repeat);
        if (rcap > sess_cap) rcap = sess_cap;

        e = run_keyboard(T(STR_PASSPHRASE_REPEAT), repeat, rcap);
        if (e != MW_OK) {
            mw_memzero(repeat, sizeof(repeat));
            mw_session_wipe_input();
            if (e == MW_ERR_ABORTED) continue;
            return e;
        }

        const size_t l1 = pp_strnlen(sess, sess_cap);
        const size_t l2 = pp_strnlen(repeat, rcap);
        const bool   same = (l1 == l2) && mw_ct_equal(sess, repeat, l1);
        mw_memzero(repeat, sizeof(repeat));

        if (!same) {
            mw_session_wipe_input();
            mw_ui_message(T(STR_ERR_GENERIC), T(STR_PASSPHRASE_MISMATCH));
            continue;
        }

        // An empty string typed twice is still an empty passphrase and still
        // needs the explicit confirmation (TZ 5.2).
        if (l1 == 0) {
            if (!confirm_empty_passphrase()) { mw_session_wipe_input(); continue; }
            mw_session_wipe_input();
            out[0] = '\0';
            return MW_OK;
        }

        memcpy(out, sess, l1);
        out[l1] = '\0';
        mw_session_wipe_input();
        return MW_OK;
    }
}
