// ============================================================================
// Device password (task2 item 1; TZ 2.0 3.1, 3.6).
//
// The seeds are sealed under a key that mixes the eFuse HMAC key with a key
// derived from a password the user types at power-on. An attacker who can
// re-flash the firmware still has the eFuse key at their disposal, but not
// the password, so the sealed records stay opaque.
//
// Derivation (record version 2, see device_auth.c for the layout)
//   PBKDF2-HMAC-SHA256 over MW_DEVICE_PW_ROUNDS rounds, split into
//   MW_DEVICE_PW_HW_STEPS chunks; after every chunk the state goes through
//   the eFuse HMAC peripheral (mw_secure_hw_hmac). The result gives pw_key
//   (-> mw_secure_user_key_set) and a verifier. Because the verifier depends
//   on the eFuse key, a copy of NVS cannot be brute-forced off the chip.
//   Records of version 1 (20000 rounds, no chip binding) are upgraded at the
//   first successful unlock, and an unbound record once eFuse is provisioned.
//
// Failed attempts: the counter is incremented and stored BEFORE the password
// is checked and cleared on success, so cutting the power at the right
// moment does not save an attempt. From the third failure on every further
// attempt is delayed for 2^(n-2) seconds, capped at 10 minutes, re-armed on
// boot.
//
// Changing the password is atomic against a power loss (pending record with
// both keys wrapped under each other; either password completes it).
//
// SPDX-License-Identifier: MIT
// ============================================================================
#ifndef MW_DEVICE_AUTH_H
#define MW_DEVICE_AUTH_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Every password that is set, changed or added: 8..64 characters. (A shorter
// one set by firmware before v7 still opens: unlocking applies no length rule.)
#define MW_DEVICE_PW_MIN      8
#define MW_DEVICE_PW_MIN_NEW  MW_DEVICE_PW_MIN
#define MW_DEVICE_PW_MAX      64
#ifndef MW_DEVICE_PW_ROUNDS
#define MW_DEVICE_PW_ROUNDS   200000u
#endif
#define MW_DEVICE_PW_HW_STEPS 8           // eFuse HMAC passes inside the KDF
#define MW_DEVICE_AUTH_REC_LEN 177        // record size in storage (version 2;
                                          // 175 before v9: no fails_total,
                                          // clean_streak)

typedef enum {
    MW_AUTH_NONE = 0,     // no password record (first start)
    MW_AUTH_SET,          // a valid record
    MW_AUTH_CORRUPT       // a record exists but cannot be read, or it is
                          // missing while wallets exist: never offer to
                          // create a new password over it
} mw_device_auth_state_t;
#define MW_DEVICE_PW_FREE_TRIES  3        // failures before the delay kicks in
#define MW_DEVICE_PW_MAX_DELAY_MS (10u * 60u * 1000u)
// v9: failures are also kept in a counter that a successful unlock does not
// clear (only ten unlocks in a row without any failure lower it by one; a
// password re-check inside a session never does). Above MW_DEVICE_PW_TOTAL_FREE it sets a delay of its own, so
// knowing one user's password does not allow unlimited guesses at another's
// by logging in between the guesses.
#define MW_DEVICE_PW_TOTAL_FREE  6

// Progress of the slow parts (the key derivation takes seconds on the
// device). Called on the task that runs verify()/set()/change(), at most once
// per 0.1 % of work, with the stage and 0..1000 within that stage. NULL
// switches it off.
enum {
    MW_AUTH_STAGE_CHECK = 1,      // checking the password
    MW_AUTH_STAGE_UPGRADE,        // one-off: moving an old record to the new KDF
    MW_AUTH_STAGE_NEW,            // deriving the key of a new password
    MW_AUTH_STAGE_REKEY           // re-sealing the wallets
};
typedef void (*mw_device_auth_progress_fn)(int stage, int permille, void* ctx);
void mw_device_auth_set_progress(mw_device_auth_progress_fn fn, void* ctx);

// Loads the stored record (if any) and arms the lockout timer.
mw_err_t mw_device_auth_init(void);
mw_device_auth_state_t mw_device_auth_state(void);
// True for MW_AUTH_SET and MW_AUTH_CORRUPT.
bool     mw_device_auth_is_set(void);

// First-time setup. Refused (MW_ERR_NOT_SUPPORTED) when a password already
// exists - use mw_device_auth_change() for that - and (MW_ERR_FORMAT) when
// the record is missing but the wallet directory is not empty. On success the user key is
// installed for this session.
mw_err_t mw_device_auth_set(const char* password);

// Checks the password.
//   The attempt is counted before the check (stored), and given back when
//   the check fails for a reason other than a wrong password.
//   MW_OK            correct; user key installed, failure counter reset in
//                    RAM and storage (a failed reset write is retried at the
//                    next verify() and at forget(), see _save_pending)
//   MW_ERR_DECRYPT   wrong password; counter incremented
//   MW_ERR_INVALID_ARG  NULL or empty string; not counted as an attempt.
//                    The 4..64 length rule of set()/change() is NOT applied
//                    here, so any non-empty string is a counted attempt.
//   MW_ERR_ABORTED   a lockout delay is still running (see _lockout_ms)
//   MW_ERR_NOT_SUPPORTED  no password set yet
mw_err_t mw_device_auth_verify(const char* password);

// True while the last write of the counter failed and is waiting for a retry.
bool     mw_device_auth_save_pending(void);

// Milliseconds until the next attempt is allowed; 0 when allowed now.
uint32_t mw_device_auth_lockout_ms(void);
uint8_t  mw_device_auth_failed_attempts(void);

// Changes the logged-in user's password (the first user's or another's):
// re-checks `old_password` against that user, re-seals its wallets under the
// key derived from `new_password` and, for the first user, stores the new
// record. Everything or nothing. MW_ERR_EXISTS: the new password is taken.
// MW_ERR_DECRYPT means only a wrong old password; a wallet record that does
// not unseal during the re-key is reported as MW_ERR_FORMAT.
mw_err_t mw_device_auth_change(const char* old_password, const char* new_password);

// ---- users (v9, see device_auth.c) ----------------------------------------
// Adds a user with its own password while someone is logged in; the new
// user's wallets are only reachable with that password, and nothing shows
// that it exists. Rules as for a new password (8..64). `name`: the account
// name (1..15 bytes; NULL or "" gives "Account").
//   MW_ERR_EXISTS        the password is taken (the first user's or another);
//                        counted as a failed attempt, since it tells as much
//                        as a login guess
//   MW_ERR_ABORTED       a lockout delay is running
//   MW_ERR_TOO_MANY      no room for another user
//   MW_ERR_NOT_SUPPORTED nobody logged in, or the record is not settled
//                        (version 2, bound to the chip, no change pending)
mw_err_t mw_device_auth_add_user(const char* password, const char* name);
// Deletes the logged-in user after re-checking its password: its wallets,
// key image caches and directory. The first user's record stays (the other
// users need its parameters) with a verifier no password matches. Logs out.
mw_err_t mw_device_auth_delete_user(const char* password);
// Re-checks that `password` is the logged-in user's (counted like an
// unlock; another user's password is "wrong" here). Never switches users.
mw_err_t mw_device_auth_check(const char* password);
// Whether add_user() is possible now.
bool     mw_device_auth_users_possible(void);

// Drops the in-RAM user key (power-off, "lock device").
void     mw_device_auth_forget(void);

// Removes the record; part of the factory reset.
mw_err_t mw_device_auth_erase(void);

// A password a stolen device would guess quickly even at the KDF's speed:
// digits only, one repeated character, or a plain run (abcdefgh, 87654321).
// The UI warns and lets the user keep it.
bool mw_device_pw_weak(const char* pw);

#ifdef __cplusplus
}
#endif
#endif
