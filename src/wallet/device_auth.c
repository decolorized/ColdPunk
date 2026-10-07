// Device password - see device_auth.h.
//
// Record "devauth" (NVS blob), version 2, REC_LEN bytes:
//
//     0    4   magic "MWDA"
//     4    1   version (2; version 1 records are still read, see below)
//     5    4   rounds  (current password)
//     9   16   salt
//     25  32   verifier
//     57   1   failed attempts            (same offset as in version 1)
//     58   1   flags: bit0 hw_bound   - the derivation used the eFuse key
//                     bit1 changing   - a password change is in progress
//                     bit2 p_hw_bound - same as bit0, for the pending one
//                     bit7 the current parameters are still version 1
//     59   4   pending rounds             -
//     63  16   pending salt                |  only meaningful while
//     79  32   pending verifier            |  "changing" is set; zero
//     111 32   wrap_new = new_key ^ H(old_key, "wrap.new")   |  otherwise
//     143 32   wrap_old = old_key ^ H(new_key, "wrap.old")  /
//
// Derivation (version 2)
//   PBKDF2-HMAC-SHA256, MW_DEVICE_PW_ROUNDS rounds in total. The PBKDF2 work is split into MW_DEVICE_PW_HW_STEPS chunks; between the
//   chunks and at the end the running state goes through the eFuse HMAC
//   peripheral (mw_secure_hw_hmac). Every guess therefore needs the chip
//   MW_DEVICE_PW_HW_STEPS times: a dump of NVS (verifier included) can no
//   longer be attacked on a GPU, only on the device, at the device's speed
//   and behind its attempt counter (audit, "verifier offline").
//
// Version 1 records (20000 rounds, no eFuse binding) are still accepted; the
// first successful unlock upgrades them, and an unbound record is upgraded
// the same way once the eFuse key has been provisioned.
//
// Atomic change (audit, "смена пароля не атомарна")
//   1. the record is written with the new parameters as "pending" and both
//      keys wrapped under each other (wrap_new / wrap_old);
//   2. the wallets are re-sealed (mw_wallet_store_rekey is idempotent);
//   3. the record is written with the new parameters as current.
//   A power loss between 1 and 3 leaves "changing" set. At the next unlock
//   either password is accepted: it opens one key, the wrap gives the other,
//   the re-key is resumed and the change completed. Nothing is ever sealed
//   under a key whose password the record does not know.
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
#define REC_VERSION  2
#define REC_LEN_V1   58
#define REC_LEN      MW_DEVICE_AUTH_REC_LEN
#define SALT_LEN     16
#define VERIFIER_LEN 32

#define FLAG_HW        0x01
#define FLAG_CHANGING  0x02
#define FLAG_P_HW      0x04
#define FLAG_CUR_V1    0x80

static const char SALT_TAG_V1[] = "mw.device.pw.v1";
static const char SALT_TAG_V2[] = "mw.device.pw.v2";
static const char VERIFY_TAG[]  = "mw.device.verify";

typedef struct {
    uint32_t rounds;
    uint8_t  version;                    // derivation version (1 or 2)
    bool     hw_bound;
    uint8_t  salt[SALT_LEN];
    uint8_t  verifier[VERIFIER_LEN];
} params_t;

typedef struct {
    bool     present;
    params_t cur;
    uint8_t  fails;
    bool     changing;
    params_t pend;
    uint8_t  wrap_new[32];
    uint8_t  wrap_old[32];
} rec_t;

static rec_t    g_rec;
static bool     g_loaded;
static bool     g_corrupt;               // a record exists but cannot be used
static uint32_t g_next_allowed_ms;       // mw_millis() value; 0 = no lockout
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

static void clear_pending(void) {
    g_rec.changing = false;
    mw_memzero(&g_rec.pend, sizeof g_rec.pend);
    mw_memzero(g_rec.wrap_new, sizeof g_rec.wrap_new);
    mw_memzero(g_rec.wrap_old, sizeof g_rec.wrap_old);
}

static mw_err_t rec_save(void) {
    uint8_t b[REC_LEN];
    memset(b, 0, sizeof b);
    b[0] = 'M'; b[1] = 'W'; b[2] = 'D'; b[3] = 'A';
    b[4] = REC_VERSION;
    put_u32(b + 5, g_rec.cur.rounds);
    memcpy(b + 9, g_rec.cur.salt, SALT_LEN);
    memcpy(b + 25, g_rec.cur.verifier, VERIFIER_LEN);
    b[57] = g_rec.fails;
    b[58] = (uint8_t)((g_rec.cur.hw_bound ? FLAG_HW : 0) |
                      (g_rec.changing ? FLAG_CHANGING : 0) |
                      (g_rec.changing && g_rec.pend.hw_bound ? FLAG_P_HW : 0) |
                      (g_rec.cur.version == 1 ? FLAG_CUR_V1 : 0));
    if (g_rec.changing) {
        put_u32(b + 59, g_rec.pend.rounds);
        memcpy(b + 63, g_rec.pend.salt, SALT_LEN);
        memcpy(b + 79, g_rec.pend.verifier, VERIFIER_LEN);
        memcpy(b + 111, g_rec.wrap_new, 32);
        memcpy(b + 143, g_rec.wrap_old, 32);
    }
    mw_err_t e = mw_store_blob_write(REC_KEY, b, sizeof b);
    mw_memzero(b, sizeof b);
    return e;
}

static bool magic_ok(const uint8_t* b) {
    return b[0] == 'M' && b[1] == 'W' && b[2] == 'D' && b[3] == 'A';
}

// MW_OK with present=false when there is no record at all; MW_ERR_FORMAT /
// MW_ERR_VERSION when one exists but cannot be interpreted (g_corrupt).
static mw_err_t rec_load(void) {
    uint8_t b[REC_LEN];
    size_t  len = 0;
    mw_err_t e = MW_OK;
    memset(&g_rec, 0, sizeof g_rec);
    g_corrupt = false;
    if (mw_store_blob_read(REC_KEY, b, sizeof b, &len) != MW_OK) return MW_OK; // none
    if (len < 5 || !magic_ok(b)) {
        e = MW_ERR_FORMAT;
    } else if (b[4] == 1 && len == REC_LEN_V1) {
        g_rec.cur.version = 1;
        g_rec.cur.rounds  = get_u32(b + 5);
        memcpy(g_rec.cur.salt, b + 9, SALT_LEN);
        memcpy(g_rec.cur.verifier, b + 25, VERIFIER_LEN);
        g_rec.fails = b[57];
    } else if (b[4] == REC_VERSION && len == REC_LEN) {
        const uint8_t fl   = b[58];
        g_rec.cur.version  = (fl & FLAG_CUR_V1) ? 1 : 2;
        g_rec.cur.hw_bound = (fl & FLAG_HW) != 0;
        g_rec.cur.rounds   = get_u32(b + 5);
        memcpy(g_rec.cur.salt, b + 9, SALT_LEN);
        memcpy(g_rec.cur.verifier, b + 25, VERIFIER_LEN);
        g_rec.fails    = b[57];
        g_rec.changing = (fl & FLAG_CHANGING) != 0;
        if (g_rec.changing) {
            g_rec.pend.version  = 2;
            g_rec.pend.hw_bound = (fl & FLAG_P_HW) != 0;
            g_rec.pend.rounds   = get_u32(b + 59);
            memcpy(g_rec.pend.salt, b + 63, SALT_LEN);
            memcpy(g_rec.pend.verifier, b + 79, VERIFIER_LEN);
            memcpy(g_rec.wrap_new, b + 111, 32);
            memcpy(g_rec.wrap_old, b + 143, 32);
            if (g_rec.pend.rounds == 0) e = MW_ERR_FORMAT;
        }
    } else {
        e = (b[4] > REC_VERSION) ? MW_ERR_VERSION : MW_ERR_FORMAT;
    }
    if (e == MW_OK && g_rec.cur.rounds == 0) e = MW_ERR_FORMAT;
    mw_memzero(b, sizeof b);
    if (e != MW_OK) {
        mw_memzero(&g_rec, sizeof g_rec);
        g_corrupt = true;
        return e;
    }
    g_rec.present = true;
    return MW_OK;
}

// Remembers whether the RAM record still has to reach storage. One log line
// per change of that state, so a dead NVS does not flood the console.
static void note_save(mw_err_t e) {
    const bool pending = (e != MW_OK);
    if (pending && !g_save_pending) {
        MW_LOGE("auth", "password record not saved (%s), will retry", mw_err_str(e));
    } else if (!pending && g_save_pending) {
        MW_LOGI("auth", "password record saved");
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

// ---------------------------------------------------------------------------
// Progress (the derivation takes seconds on the device)
// ---------------------------------------------------------------------------
static mw_device_auth_progress_fn g_prog_fn;
static void*                      g_prog_ctx;
static int                        g_prog_stage;
static uint64_t                   g_prog_done, g_prog_total;
static int                        g_prog_last = -1;

void mw_device_auth_set_progress(mw_device_auth_progress_fn fn, void* ctx) {
    g_prog_fn  = fn;
    g_prog_ctx = ctx;
}

static void prog_report(void) {
    if (!g_prog_fn) return;
    int pm = g_prog_total ? (int)(g_prog_done * 1000u / g_prog_total) : 0;
    if (pm > 1000) pm = 1000;
    if (pm == g_prog_last) return;           // the screen only redraws on a change
    g_prog_last = pm;
    g_prog_fn(g_prog_stage, pm, g_prog_ctx);
}

// Starts a stage whose work is `total` PBKDF2 iterations.
static void prog_stage(int stage, uint64_t total) {
    g_prog_stage = stage;
    g_prog_done  = 0;
    g_prog_total = total;
    g_prog_last  = -1;
    prog_report();
}

static void prog_tick(uint32_t iterations, void* ctx) {
    (void)ctx;
    g_prog_done += iterations;
    prog_report();
}

static void prog_finish(void) {
    g_prog_done = g_prog_total;
    prog_report();
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------
// One pass through the eFuse HMAC: out = HW(tag || step || state).
// Parameters made before the eFuse key existed (hw_bound false) keep using
// the public bring-up constant of mw_secure_hw_hmac() even after the key
// has been provisioned, so such a record still opens and can be upgraded.
static const char HW_FALLBACK_KEY[] = "mw.hw.hmac.fallback (eFuse not provisioned)";

static mw_err_t hw_step(const char* tag, uint8_t step, const uint8_t state[32],
                        bool want_bound, uint8_t out[32]) {
    uint8_t msg[24 + 1 + 32];
    const size_t tl = strlen(tag);
    mw_err_t e = MW_OK;
    if (tl > 24) return MW_ERR_INVALID_ARG;
    memcpy(msg, tag, tl);
    msg[tl] = step;
    memcpy(msg + tl + 1, state, 32);
    if (want_bound) {
        bool bound = false;
        e = mw_secure_hw_hmac(msg, tl + 1 + 32, out, &bound);
        if (e == MW_OK && !bound) e = MW_ERR_NOT_SUPPORTED;   // eFuse key gone
    } else {
        mw_hmac_sha256((const uint8_t*)HW_FALLBACK_KEY, sizeof HW_FALLBACK_KEY - 1,
                       msg, tl + 1 + 32, out);
    }
    mw_memzero(msg, sizeof msg);
    return e;
}

// pw_key[32] and the verifier from the password and a parameter set.
//   MW_ERR_NOT_SUPPORTED  the parameters need the eFuse key and it is not
//                         available (or the other way round)
static mw_err_t derive(const char* pw, const params_t* p,
                       uint8_t pw_key[32], uint8_t verifier[VERIFIER_LEN]) {
    uint8_t out[64];
    mw_err_t e = MW_OK;
    const uint64_t prog_base = g_prog_done;
    mw_pbkdf2_set_progress(g_prog_fn ? prog_tick : NULL, NULL);

    if (p->version == 1) {
        uint8_t full_salt[SALT_LEN + sizeof(SALT_TAG_V1) - 1];
        memcpy(full_salt, p->salt, SALT_LEN);
        memcpy(full_salt + SALT_LEN, SALT_TAG_V1, sizeof(SALT_TAG_V1) - 1);
        mw_pbkdf2_sha512((const uint8_t*)pw, strlen(pw), full_salt, sizeof full_salt,
                         p->rounds, out, sizeof out);
        mw_memzero(full_salt, sizeof full_salt);
        g_prog_done = prog_base + p->rounds;          // the ticks miss the tail
        prog_report();
    } else {
        // PBKDF2-HMAC-SHA256: on the 32-bit Xtensa core SHA-256 is several
        // times faster than SHA-512 per round, so the same unlock time buys
        // far more rounds.
        uint8_t salt[SALT_LEN + sizeof(SALT_TAG_V2) - 1 + 1];
        uint8_t state[32], next_pw[32 + 32], h[32];
        const unsigned steps = MW_DEVICE_PW_HW_STEPS;
        uint32_t per = p->rounds / steps;
        if (per == 0) per = 1;

        memcpy(salt, p->salt, SALT_LEN);
        memcpy(salt + SALT_LEN, SALT_TAG_V2, sizeof(SALT_TAG_V2) - 1);
        salt[sizeof salt - 1] = 0;
        mw_pbkdf2_sha256((const uint8_t*)pw, strlen(pw), salt, sizeof salt, per,
                         state, sizeof state);
        g_prog_done = prog_base + per;                // exact after each chunk
        prog_report();
        for (unsigned i = 1; i < steps; ++i) {
            e = hw_step("mw.pw.hw", (uint8_t)i, state, p->hw_bound, h);
            if (e != MW_OK) break;
            // ~1/8 of the work per chunk: let lower-priority tasks on this
            // core (idle, Arduino loop) run between the chunks.
            mw_delay_ms(1);
            memcpy(next_pw, state, 32);
            memcpy(next_pw + 32, h, 32);
            salt[sizeof salt - 1] = (uint8_t)i;
            mw_pbkdf2_sha256(next_pw, sizeof next_pw, salt, sizeof salt, per,
                             state, sizeof state);
            g_prog_done = prog_base + (uint64_t)per * (i + 1);
            prog_report();
        }
        if (e == MW_OK) e = hw_step("mw.pw.hw.final", 0, state, p->hw_bound, h);
        if (e == MW_OK) mw_hmac_sha512(h, sizeof h, state, sizeof state, out);
        mw_memzero(state, sizeof state);
        mw_memzero(next_pw, sizeof next_pw);
        mw_memzero(h, sizeof h);
        mw_memzero(salt, sizeof salt);
    }
    mw_pbkdf2_set_progress(NULL, NULL);
    if (e == MW_OK) {
        memcpy(pw_key, out, 32);
        mw_hmac_sha256(out + 32, 32, (const uint8_t*)VERIFY_TAG, sizeof(VERIFY_TAG) - 1,
                       verifier);
    }
    mw_memzero(out, sizeof out);
    return e;
}

// Whether the eFuse key is usable right now.
static mw_err_t hw_available(bool* bound) {
    uint8_t probe[32];
    mw_err_t e = mw_secure_hw_hmac((const uint8_t*)"probe", 5, probe, bound);
    mw_memzero(probe, sizeof probe);
    return e;
}

// Fresh version-2 parameters for `pw`; *key receives its user key. Bound to
// the chip whenever the eFuse key is provisioned.
static mw_err_t new_params(const char* pw, params_t* p, uint8_t key[32]) {
    bool bound = false;
    memset(p, 0, sizeof *p);
    mw_err_t e = hw_available(&bound);
    if (e != MW_OK) return e;
    p->version  = 2;
    p->hw_bound = bound;
    p->rounds   = MW_DEVICE_PW_ROUNDS;
    mw_random_bytes(p->salt, SALT_LEN);
    return derive(pw, p, key, p->verifier);
}

// wrap = key ^ HMAC-SHA256(other, tag); the same call unwraps.
static void wrap_key(const uint8_t key[32], const uint8_t other[32], const char* tag,
                     uint8_t out[32]) {
    uint8_t m[32];
    mw_hmac_sha256(other, 32, (const uint8_t*)tag, strlen(tag), m);
    for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(key[i] ^ m[i]);
    mw_memzero(m, sizeof m);
}

// ---------------------------------------------------------------------------
mw_err_t mw_device_auth_init(void) {
    mw_err_t e = rec_load();
    g_loaded = true;
    g_save_pending = false;                 // RAM == storage again
    if (e != MW_OK) {
        MW_LOGE("auth", "password record unreadable (%s)", mw_err_str(e));
        return e;
    }
    arm_lockout();
    return MW_OK;
}

static mw_err_t ensure_loaded(void) {
    if (!g_loaded) return mw_device_auth_init();
    return g_corrupt ? MW_ERR_FORMAT : MW_OK;
}

mw_device_auth_state_t mw_device_auth_state(void) {
    (void)ensure_loaded();
    if (g_corrupt) return MW_AUTH_CORRUPT;
    if (g_rec.present) return MW_AUTH_SET;
    // No record at all, but wallets: the record was lost (worn NVS page,
    // partial erase). Creating a password now would derive a different key
    // and orphan every wallet.
    uint32_t wallets = 0;
    if (mw_wallet_store_count(&wallets) != MW_OK || wallets != 0) return MW_AUTH_CORRUPT;
    return MW_AUTH_NONE;
}

bool mw_device_auth_is_set(void) {
    // A damaged record counts as "set": nothing may offer to create a new
    // password over it. Callers that care ask mw_device_auth_state().
    return mw_device_auth_state() != MW_AUTH_NONE;
}

mw_err_t mw_device_auth_set(const char* password) {
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (g_rec.present) return MW_ERR_NOT_SUPPORTED;
    if (!password_ok(password)) return MW_ERR_INVALID_ARG;
    if (mw_device_auth_state() != MW_AUTH_NONE) {
        MW_LOGE("auth", "no password record but the wallet store is not empty: "
                        "refusing to create a new password");
        return MW_ERR_FORMAT;
    }

    uint8_t key[32];
    rec_t rec;
    memset(&rec, 0, sizeof rec);
    prog_stage(MW_AUTH_STAGE_NEW, MW_DEVICE_PW_ROUNDS);
    e = new_params(password, &rec.cur, key);
    prog_finish();
    if (e != MW_OK) { mw_memzero(key, sizeof key); return e; }
    rec.present = true;
    g_rec = rec;
    mw_memzero(&rec, sizeof rec);

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

// Makes `next` (whose key is new_key) the current password, re-keying the
// wallets from old_key. With `resume` the pending record is already in
// storage (an interrupted change being completed).
static mw_err_t switch_password(const params_t* next, const uint8_t old_key[32],
                                const uint8_t new_key[32], bool resume) {
    mw_err_t e;
    if (!resume) {
        g_rec.pend     = *next;
        g_rec.changing = true;
        wrap_key(new_key, old_key, "wrap.new", g_rec.wrap_new);
        wrap_key(old_key, new_key, "wrap.old", g_rec.wrap_old);
        e = rec_save();                       // step 1: both keys recoverable
        if (e != MW_OK) {
            clear_pending();
            (void)mw_secure_user_key_set(old_key);
            return e;
        }
    }

    prog_stage(MW_AUTH_STAGE_REKEY, 1);
    e = mw_wallet_store_rekey(old_key, new_key);   // step 2, idempotent
    prog_finish();
    if (e != MW_OK) {
        // Back to the old password: re-seal whatever was converted (also
        // idempotent) and drop the pending part.
        (void)mw_wallet_store_rekey(new_key, old_key);
        clear_pending();
        (void)rec_commit();
        (void)mw_secure_user_key_set(old_key);
        // The passwords were checked, so a record that does not unseal is
        // damaged or foreign - not a wrong password.
        return (e == MW_ERR_DECRYPT) ? MW_ERR_FORMAT : e;
    }

    g_rec.cur = g_rec.pend;                        // step 3
    clear_pending();
    g_rec.fails = 0;
    if (rec_commit() != MW_OK) {
        // The wallets are under new_key and storage still says "changing"
        // with both keys recoverable: the next unlock (either password)
        // finishes the job, and retry_pending() tries the write again.
        MW_LOGE("auth", "password change: final record write failed, will complete later");
    }
    return mw_secure_user_key_set(new_key);
}

// Checks `password` against the record. On success *key holds the key of
// the current password (after completing an interrupted change, if any).
static mw_err_t check(const char* password, uint8_t key[32]) {
    uint8_t ver[VERIFIER_LEN], other[32];
    prog_stage(MW_AUTH_STAGE_CHECK,
               (uint64_t)g_rec.cur.rounds + (g_rec.changing ? g_rec.pend.rounds : 0));
    mw_err_t e = derive(password, &g_rec.cur, key, ver);
    bool ok = (e == MW_OK) && mw_ct_equal(ver, g_rec.cur.verifier, VERIFIER_LEN) != 0;

    if (g_rec.changing) {
        params_t next = g_rec.pend;
        if (ok) {
            // The old password: the new key comes out of wrap_new.
            wrap_key(g_rec.wrap_new, key, "wrap.new", other);
            MW_LOGI("auth", "completing an interrupted password change");
            e = switch_password(&next, key, other, true);
            memcpy(key, other, 32);
        } else if (derive(password, &next, key, ver) == MW_OK &&
                   mw_ct_equal(ver, next.verifier, VERIFIER_LEN)) {
            ok = true;
            wrap_key(g_rec.wrap_old, key, "wrap.old", other);
            MW_LOGI("auth", "completing an interrupted password change");
            e = switch_password(&next, other, key, true);
        }
        mw_memzero(&next, sizeof next);
    }
    mw_memzero(ver, sizeof ver);
    mw_memzero(other, sizeof other);
    if (!ok) {
        mw_memzero(key, 32);
        return (e == MW_OK) ? MW_ERR_DECRYPT : e;
    }
    if (e != MW_OK) mw_memzero(key, 32);
    return e;
}

// Brings an old record up to the current derivation (version 2, current
// round count, eFuse binding once available). Best effort: the unlock that
// triggered it has already succeeded, and on failure the old record stays.
static void maybe_upgrade(const char* password, const uint8_t key[32]) {
    bool bound = false;
    if (hw_available(&bound) != MW_OK) return;
    const bool stale = g_rec.cur.version < 2 || g_rec.cur.rounds < MW_DEVICE_PW_ROUNDS ||
                       (bound && !g_rec.cur.hw_bound);
    if (!stale) return;

    params_t next;
    uint8_t  new_key[32];
    prog_stage(MW_AUTH_STAGE_UPGRADE, MW_DEVICE_PW_ROUNDS);
    if (new_params(password, &next, new_key) == MW_OK) {
        MW_LOGI("auth", "upgrading the password record (v%u, %u rounds%s -> v2, %u rounds%s)",
                (unsigned)g_rec.cur.version, (unsigned)g_rec.cur.rounds,
                g_rec.cur.hw_bound ? ", eFuse" : "", (unsigned)next.rounds,
                next.hw_bound ? ", eFuse" : "");
        if (switch_password(&next, key, new_key, false) != MW_OK)
            MW_LOGE("auth", "password record upgrade failed; the old one stays valid");
    }
    mw_memzero(&next, sizeof next);
    mw_memzero(new_key, sizeof new_key);
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

    // The attempt is counted and stored BEFORE the (slow, power-visible)
    // check: cutting the power once the result shows on the supply line no
    // longer saves an attempt. A success clears the counter again below.
    const uint8_t fails_before = g_rec.fails;
    if (g_rec.fails < 255) g_rec.fails++;
    (void)rec_commit();

    uint8_t key[32];
    const uint32_t t0 = mw_millis();
    e = check(password, key);
    // For tuning MW_DEVICE_PW_ROUNDS on a given board (UART only: "[auth]"
    // lines never leave the device over USB).
    MW_LOGD("auth", "password check took %u ms (%u rounds)",
            (unsigned)(mw_millis() - t0), (unsigned)g_rec.cur.rounds);
    if (e == MW_ERR_DECRYPT) {
        arm_lockout();
        return MW_ERR_DECRYPT;
    }
    if (e != MW_OK) {
        // Not a wrong password (eFuse unavailable, re-key failure): give the
        // attempt back.
        g_rec.fails = fails_before;
        (void)rec_commit();
        return e;
    }

    e = mw_secure_user_key_set(key);
    if (e != MW_OK) { mw_memzero(key, sizeof key); return e; }
    // The counter was raised before the check, so the reset is always
    // written. The unlock itself never depends on the write: refusing it
    // would lock the owner out; a failed write is retried (retry_pending).
    g_rec.fails = 0;
    g_next_allowed_ms = 0;
    (void)rec_commit();

    maybe_upgrade(password, key);
    mw_memzero(key, sizeof key);
    return MW_OK;
}

mw_err_t mw_device_auth_change(const char* old_password, const char* new_password) {
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (!g_rec.present) return MW_ERR_NOT_SUPPORTED;
    if (!password_ok(new_password)) return MW_ERR_INVALID_ARG;

    // The old password proves the caller may re-key; verify() also leaves the
    // current user key installed, which the re-key needs.
    e = mw_device_auth_verify(old_password);
    if (e != MW_OK) return e;

    uint8_t old_key[32], new_key[32], ver[VERIFIER_LEN];
    params_t next;
    memset(&next, 0, sizeof next);
    prog_stage(MW_AUTH_STAGE_NEW, (uint64_t)g_rec.cur.rounds + MW_DEVICE_PW_ROUNDS);
    e = derive(old_password, &g_rec.cur, old_key, ver);
    mw_memzero(ver, sizeof ver);
    if (e == MW_OK) e = new_params(new_password, &next, new_key);
    if (e == MW_OK) e = switch_password(&next, old_key, new_key, false);

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
    g_corrupt = false;
    g_loaded = true;
    mw_err_t e = mw_store_blob_erase(REC_KEY);
    return (e == MW_OK || e == MW_ERR_IO) ? MW_OK : e;   // "not found" is fine
}
