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

#define MW_DEVICE_PW_MIN      4
#define MW_DEVICE_PW_MAX      64
#ifndef MW_DEVICE_PW_ROUNDS
#define MW_DEVICE_PW_ROUNDS   200000u
#endif
#define MW_DEVICE_PW_HW_STEPS 8           // eFuse HMAC passes inside the KDF
#define MW_DEVICE_AUTH_REC_LEN 175        // record size in storage (version 2)

typedef enum {
    MW_AUTH_NONE = 0,     // no password record (first start)
    MW_AUTH_SET,          // a valid record
    MW_AUTH_CORRUPT       // a record exists but cannot be read, or it is
                          // missing while wallets exist: never offer to
                          // create a new password over it
} mw_device_auth_state_t;
#define MW_DEVICE_PW_FREE_TRIES  3        // failures before the delay kicks in
#define MW_DEVICE_PW_MAX_DELAY_MS (10u * 60u * 1000u)

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

// Verifies `old_password`, re-seals every wallet under the key derived from
// `new_password` and stores the new record. Everything or nothing.
// MW_ERR_DECRYPT means only a wrong old password; a wallet record that does
// not unseal during the re-key is reported as MW_ERR_FORMAT.
mw_err_t mw_device_auth_change(const char* old_password, const char* new_password);

// Drops the in-RAM user key (power-off, "lock device").
void     mw_device_auth_forget(void);

// Removes the record; part of the factory reset.
mw_err_t mw_device_auth_erase(void);

#ifdef __cplusplus
}
#endif
#endif
