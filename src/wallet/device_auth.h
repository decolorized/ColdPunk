// ============================================================================
// Device password (task2 item 1; TZ 2.0 3.1, 3.6).
//
// The seeds are sealed under a key that mixes the eFuse HMAC key with a key
// derived from a password the user types at power-on. An attacker who can
// re-flash the firmware still has the eFuse key at their disposal, but not
// the password, so the sealed records stay opaque.
//
// Derivation
//   pw_key || verify_key = PBKDF2-HMAC-SHA512(password,
//                              salt16 || "mw.device.pw.v1", MW_DEVICE_PW_ROUNDS)
//   stored:   salt16, verifier = HMAC-SHA256(verify_key, "mw.device.verify")
//   in RAM:   pw_key -> mw_secure_user_key_set()
//
// The verifier lets the boot screen check the password without touching any
// wallet record and without keeping anything that would help derive pw_key.
//
// Brute force (TZ 3.6 "Задержка после N попыток"): the failed-attempt counter
// is persisted; from the third failure on every further attempt is delayed
// for 2^(n-2) seconds, capped at 10 minutes, and the delay is re-armed on
// boot so a power cycle does not reset it.
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
#define MW_DEVICE_PW_ROUNDS   20000u
#define MW_DEVICE_PW_FREE_TRIES  3        // failures before the delay kicks in
#define MW_DEVICE_PW_MAX_DELAY_MS (10u * 60u * 1000u)

// Loads the stored record (if any) and arms the lockout timer.
mw_err_t mw_device_auth_init(void);
bool     mw_device_auth_is_set(void);

// First-time setup. Refused (MW_ERR_NOT_SUPPORTED) when a password already
// exists - use mw_device_auth_change() for that. On success the user key is
// installed for this session.
mw_err_t mw_device_auth_set(const char* password);

// Checks the password.
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
