// Device password - see device_auth.h.
//
// SPDX-License-Identifier: MIT
#include "device_auth.h"
#include "secure_storage.h"
#include "wallet_store.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"
#include "../hal/hal.h"
#include "../hal/log.h"

#include <string.h>

// Platform blob API (secure_storage.cpp / secure_storage_host.c).
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);

#define REC_KEY      "devauth"
#define REC_VERSION  1
// magic(4) version(1) rounds(4) salt(16) verifier(32) fails(1)
#define REC_LEN      58
#define SALT_LEN     16
#define VERIFIER_LEN 32

static const char SALT_TAG[]   = "mw.device.pw.v1";
static const char VERIFY_TAG[] = "mw.device.verify";

typedef struct {
    bool     present;
    uint32_t rounds;
    uint8_t  salt[SALT_LEN];
    uint8_t  verifier[VERIFIER_LEN];
    uint8_t  fails;
} rec_t;

static rec_t    g_rec;
static bool     g_loaded;
static uint32_t g_next_allowed_ms;      // mw_millis() value; 0 = no lockout
// The RAM record is newer than storage: the last write of it failed. Retried
// at the next verify() and at forget(), never from a getter.
static bool     g_save_pending;

// ---------------------------------------------------------------------------
static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static mw_err_t rec_save(void) {
    uint8_t b[REC_LEN];
    memset(b, 0, sizeof b);
    b[0] = 'M'; b[1] = 'W'; b[2] = 'D'; b[3] = 'A';
    b[4] = REC_VERSION;
    put_u32(b + 5, g_rec.rounds);
    memcpy(b + 9, g_rec.salt, SALT_LEN);
    memcpy(b + 25, g_rec.verifier, VERIFIER_LEN);
    b[57] = g_rec.fails;
    mw_err_t e = mw_store_blob_write(REC_KEY, b, sizeof b);
    mw_memzero(b, sizeof b);
    return e;
}

static mw_err_t rec_load(void) {
    uint8_t b[REC_LEN];
    size_t  len = 0;
    memset(&g_rec, 0, sizeof g_rec);
    if (mw_store_blob_read(REC_KEY, b, sizeof b, &len) != MW_OK) return MW_OK; // none
    if (len != REC_LEN || b[0] != 'M' || b[1] != 'W' || b[2] != 'D' || b[3] != 'A')
        return MW_ERR_FORMAT;
    if (b[4] != REC_VERSION) return MW_ERR_VERSION;
    g_rec.rounds = get_u32(b + 5);
    memcpy(g_rec.salt, b + 9, SALT_LEN);
    memcpy(g_rec.verifier, b + 25, VERIFIER_LEN);
    g_rec.fails  = b[57];
    g_rec.present = (g_rec.rounds != 0);
    mw_memzero(b, sizeof b);
    return MW_OK;
}

// The failure counter as storage holds it; -1 when the record cannot be read.
static int stored_fails(void) {
    uint8_t b[REC_LEN];
    size_t  len = 0;
    int     f   = -1;
    if (mw_store_blob_read(REC_KEY, b, sizeof b, &len) == MW_OK && len == REC_LEN &&
        b[0] == 'M' && b[1] == 'W' && b[2] == 'D' && b[3] == 'A') {
        f = b[57];
    }
    mw_memzero(b, sizeof b);
    return f;
}

// Remembers whether the RAM record still has to reach storage. One log line
// per change of that state, so a dead NVS does not flood the console.
static void note_save(mw_err_t e) {
    const bool pending = (e != MW_OK);
    if (pending && !g_save_pending) {
        MW_LOGE("auth", "failed-attempt counter not saved (%s), will retry",
                mw_err_str(e));
    } else if (!pending && g_save_pending) {
        MW_LOGI("auth", "failed-attempt counter saved");
    }
    g_save_pending = pending;
}

static mw_err_t rec_commit(void) {
    const mw_err_t e = rec_save();
    note_save(e);
    return e;
}

static void retry_pending(void) {
    if (g_save_pending) (void)rec_commit();
}

static uint32_t delay_for(uint8_t fails) {
    if (fails < MW_DEVICE_PW_FREE_TRIES) return 0;
    unsigned shift = (unsigned)fails - (MW_DEVICE_PW_FREE_TRIES - 1);   // 3 -> 1
    if (shift > 20) shift = 20;
    uint32_t ms = 1000u << shift;                                       // 2s, 4s, 8s ...
    if (ms > MW_DEVICE_PW_MAX_DELAY_MS) ms = MW_DEVICE_PW_MAX_DELAY_MS;
    return ms;
}

static void arm_lockout(void) {
    uint32_t d = delay_for(g_rec.fails);
    g_next_allowed_ms = d ? (mw_millis() + d) : 0;
    if (g_next_allowed_ms == 0 && d) g_next_allowed_ms = 1;   // never confuse with "none"
}

static bool password_ok(const char* pw) {
    if (!pw) return false;
    size_t n = strlen(pw);
    return n >= MW_DEVICE_PW_MIN && n <= MW_DEVICE_PW_MAX;
}

// pw_key[32] || verify_key[32] from the password and the record's salt/rounds.
static void derive(const char* pw, const uint8_t salt[SALT_LEN], uint32_t rounds,
                   uint8_t pw_key[32], uint8_t verifier[VERIFIER_LEN]) {
    uint8_t full_salt[SALT_LEN + sizeof(SALT_TAG) - 1];
    uint8_t out[64];
    memcpy(full_salt, salt, SALT_LEN);
    memcpy(full_salt + SALT_LEN, SALT_TAG, sizeof(SALT_TAG) - 1);
    mw_pbkdf2_sha512((const uint8_t*)pw, strlen(pw), full_salt, sizeof full_salt,
                     rounds, out, sizeof out);
    memcpy(pw_key, out, 32);
    mw_hmac_sha256(out + 32, 32, (const uint8_t*)VERIFY_TAG, sizeof(VERIFY_TAG) - 1,
                   verifier);
    mw_memzero(out, sizeof out);
    mw_memzero(full_salt, sizeof full_salt);
}

// ---------------------------------------------------------------------------
mw_err_t mw_device_auth_init(void) {
    mw_err_t e = rec_load();
    g_loaded = true;
    g_save_pending = false;                 // RAM == storage again
    if (e != MW_OK) return e;
    arm_lockout();
    return MW_OK;
}

static mw_err_t ensure_loaded(void) {
    return g_loaded ? MW_OK : mw_device_auth_init();
}

bool mw_device_auth_is_set(void) {
    if (ensure_loaded() != MW_OK) return false;
    return g_rec.present;
}

mw_err_t mw_device_auth_set(const char* password) {
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (g_rec.present) return MW_ERR_NOT_SUPPORTED;
    if (!password_ok(password)) return MW_ERR_INVALID_ARG;

    uint8_t key[32];
    memset(&g_rec, 0, sizeof g_rec);
    g_rec.rounds = MW_DEVICE_PW_ROUNDS;
    mw_random_bytes(g_rec.salt, SALT_LEN);
    derive(password, g_rec.salt, g_rec.rounds, key, g_rec.verifier);
    g_rec.fails   = 0;
    g_rec.present = true;

    e = rec_save();
    if (e == MW_OK) e = mw_secure_user_key_set(key);
    if (e != MW_OK) {
        memset(&g_rec, 0, sizeof g_rec);
        (void)mw_store_blob_erase(REC_KEY);
    }
    mw_memzero(key, sizeof key);
    g_next_allowed_ms = 0;
    g_save_pending    = false;
    return e;
}

uint32_t mw_device_auth_lockout_ms(void) {
    if (ensure_loaded() != MW_OK) return 0;
    if (g_next_allowed_ms == 0) return 0;
    int32_t left = (int32_t)(g_next_allowed_ms - mw_millis());
    if (left <= 0) { g_next_allowed_ms = 0; return 0; }
    return (uint32_t)left;
}

uint8_t mw_device_auth_failed_attempts(void) {
    if (ensure_loaded() != MW_OK) return 0;
    return g_rec.fails;
}

bool mw_device_auth_save_pending(void) {
    return g_save_pending;
}

mw_err_t mw_device_auth_verify(const char* password) {
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    retry_pending();
    if (!g_rec.present) return MW_ERR_NOT_SUPPORTED;
    // An empty submission (a stray Enter) is not an attempt. Any non-empty
    // string is: the 4..64 rule of set()/change() is not applied here.
    if (!password || !password[0]) return MW_ERR_INVALID_ARG;
    if (mw_device_auth_lockout_ms() > 0) return MW_ERR_ABORTED;

    uint8_t key[32], ver[VERIFIER_LEN];
    derive(password, g_rec.salt, g_rec.rounds, key, ver);
    const bool ok = mw_ct_equal(ver, g_rec.verifier, VERIFIER_LEN) != 0;
    mw_memzero(ver, sizeof ver);

    if (!ok) {
        mw_memzero(key, sizeof key);
        if (g_rec.fails < 255) g_rec.fails++;
        (void)rec_commit();                 // the counter must survive a reboot
        arm_lockout();
        return MW_ERR_DECRYPT;
    }

    e = mw_secure_user_key_set(key);
    mw_memzero(key, sizeof key);
    if (e != MW_OK) return e;
    // Storage is checked as well as RAM, so a reset that once failed to
    // reach storage is written by the next success. The unlock itself never
    // depends on the write: refusing it would lock the owner out.
    const bool dirty = g_rec.fails != 0 || g_save_pending || stored_fails() != 0;
    g_rec.fails = 0;
    g_next_allowed_ms = 0;
    if (dirty) (void)rec_commit();
    return MW_OK;
}

mw_err_t mw_device_auth_change(const char* old_password, const char* new_password) {
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (!g_rec.present) return MW_ERR_NOT_SUPPORTED;
    if (!password_ok(new_password)) return MW_ERR_INVALID_ARG;

    // The old password proves the caller may re-key; it also leaves the OLD
    // user key installed, which the rekey needs to unseal every record.
    e = mw_device_auth_verify(old_password);
    if (e != MW_OK) return e;

    uint8_t old_key[32], new_key[32];
    uint8_t old_ver[VERIFIER_LEN];
    rec_t   next;

    derive(old_password, g_rec.salt, g_rec.rounds, old_key, old_ver);
    mw_memzero(old_ver, sizeof old_ver);

    memset(&next, 0, sizeof next);
    next.rounds  = MW_DEVICE_PW_ROUNDS;
    next.present = true;
    mw_random_bytes(next.salt, SALT_LEN);
    derive(new_password, next.salt, next.rounds, new_key, next.verifier);

    e = mw_wallet_store_rekey(old_key, new_key);   // leaves new_key installed on success
    // The old password was verified above, so a record that does not unseal
    // under its key is damaged or foreign - not a wrong password.
    if (e == MW_ERR_DECRYPT) e = MW_ERR_FORMAT;
    if (e == MW_OK) {
        rec_t prev = g_rec;
        g_rec = next;
        e = rec_save();
        if (e != MW_OK) {
            // Storage refused the new record: put the old key back so the
            // (already re-sealed) wallets are re-keyed back as well.
            g_rec = prev;
            (void)mw_wallet_store_rekey(new_key, old_key);
        } else {
            note_save(MW_OK);               // the whole record, fails = 0, is stored
        }
    } else {
        (void)mw_secure_user_key_set(old_key);
    }

    mw_memzero(old_key, sizeof old_key);
    mw_memzero(new_key, sizeof new_key);
    mw_memzero(&next, sizeof next);
    return e;
}

void mw_device_auth_forget(void) {
    retry_pending();
    mw_secure_user_key_clear();
}

mw_err_t mw_device_auth_erase(void) {
    mw_secure_user_key_clear();
    memset(&g_rec, 0, sizeof g_rec);
    g_next_allowed_ms = 0;
    g_save_pending    = false;
    g_loaded = true;
    mw_err_t e = mw_store_blob_erase(REC_KEY);
    return (e == MW_OK || e == MW_ERR_IO) ? MW_OK : e;   // "not found" is fine
}
