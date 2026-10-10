// Device password (task2 item 1): set / verify / lockout / change + rekey,
// and the rule that nothing seals without the user key.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"

#include "crypto/hash.h"
#include "crypto/memzero.h"
#include "crypto/random.h"
#include "monero/address.h"
#include "monero/mnemonic.h"
#include "wallet/device_auth.h"
#include "wallet/file_store.h"
#include "wallet/secure_storage.h"
#include "wallet/wallet_store.h"
#include "hal/hal.h"

#include <string.h>

// Host-backend hooks (not part of the frozen API).
void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);
void mw_settings_test_set_display(int has_touch, int width, int height);
void mw_host_advance_ms(uint32_t ms);
void mw_host_store_fail_writes(const char* key, int n);
void mw_host_store_fail_reads(const char* key, int n);
void mw_host_store_fail_writes_after(const char* key, int skip, int n);
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);

#define STORE_DIR "./.mw_test_devauth_store"

static void fresh(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 240, 320);
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);     // drop the cached directory
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
}

MW_TEST(test_no_password_yet)
{
    fresh();
    CHECK(!mw_device_auth_is_set());
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_verify("anything"), MW_ERR_NOT_SUPPORTED);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);

    // Without a user key nothing can be sealed: a wallet cannot be created.
    uint8_t seed[32];
    uint32_t id = 0;
    memset(seed, 0x42, sizeof seed);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_create("NoKey", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id),
                 MW_ERR_NOT_SUPPORTED);
}

MW_TEST(test_set_rules_and_verify)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("abc"), MW_ERR_INVALID_ARG);        // too short
    {
        char too_long[MW_DEVICE_PW_MAX + 2];
        memset(too_long, 'x', sizeof too_long);
        too_long[sizeof too_long - 1] = '\0';
        CHECK_EQ_INT(mw_device_auth_set(too_long), MW_ERR_INVALID_ARG);
    }
    CHECK_EQ_INT(mw_device_auth_set(NULL), MW_ERR_INVALID_ARG);

    CHECK_EQ_INT(mw_device_auth_set("correct horse"), MW_OK);
    CHECK(mw_device_auth_is_set());
    CHECK(mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_set("another"), MW_ERR_NOT_SUPPORTED);  // already set

    // Power cycle: the key is gone, the record is not.
    mw_device_auth_forget();
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK(mw_device_auth_is_set());

    CHECK_EQ_INT(mw_device_auth_verify("wrong"), MW_ERR_DECRYPT);
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);
    CHECK_EQ_INT(mw_device_auth_verify("Correct horse"), MW_ERR_DECRYPT); // case matters
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 2);
    CHECK_EQ_INT(mw_device_auth_verify("correct horse"), MW_OK);
    CHECK(mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
}

MW_TEST(test_lockout_after_failures)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("password1"), MW_OK);
    mw_device_auth_forget();

    CHECK_EQ_INT(mw_device_auth_verify("x1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("x2"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);              // two free tries
    CHECK_EQ_INT(mw_device_auth_verify("x3"), MW_ERR_DECRYPT);  // third -> delay
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 3);
    CHECK(mw_device_auth_lockout_ms() > 0u);
    CHECK(mw_device_auth_lockout_ms() <= 2000u);

    // While the delay runs even the right password is refused, and the
    // refusal does not count as another failure.
    CHECK_EQ_INT(mw_device_auth_verify("password1"), MW_ERR_ABORTED);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 3);

    // The counter is persisted: a "reboot" re-arms the delay.
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK(mw_device_auth_lockout_ms() > 0u);

    mw_host_advance_ms(2500);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
    CHECK_EQ_INT(mw_device_auth_verify("x4"), MW_ERR_DECRYPT);  // fourth -> 4 s
    CHECK(mw_device_auth_lockout_ms() > 2000u);
    CHECK(mw_device_auth_lockout_ms() <= 4000u);
    mw_host_advance_ms(4500);
    CHECK_EQ_INT(mw_device_auth_verify("password1"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
}

MW_TEST(test_change_password_rekeys_wallets)
{
    uint8_t seed[32];
    uint32_t id_a = 0, id_b = 0;
    mw_account_keys_t before, after;
    char addr_before[MW_ADDRESS_STR_MAX], addr_after[MW_ADDRESS_STR_MAX];
    mw_address_t addr;

    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-pw"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);

    memset(seed, 0x5a, sizeof seed);
    CHECK_EQ_INT(mw_wallet_create("A", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id_a), MW_OK);
    memset(seed, 0xa5, sizeof seed);
    CHECK_EQ_INT(mw_wallet_create("B", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id_b), MW_OK);

    memset(&before, 0, sizeof before);
    CHECK_EQ_INT(mw_wallet_load_keys(id_b, "", &before), MW_OK);
    CHECK_EQ_INT(mw_address_from_keys(&before, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, addr_before, sizeof addr_before), MW_OK);

    // Wrong old password: nothing changes, and the failure is counted.
    CHECK_EQ_INT(mw_device_auth_change("nope-nope", "second-pw"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);
    // A too-short new password is refused before anything is touched.
    CHECK_EQ_INT(mw_device_auth_change("first-pw", "ab"), MW_ERR_INVALID_ARG);

    CHECK_EQ_INT(mw_device_auth_change("first-pw", "second-pw"), MW_OK);
    CHECK(mw_secure_user_key_present());

    // Same wallet, same keys, straight after the change ...
    memset(&after, 0, sizeof after);
    CHECK_EQ_INT(mw_wallet_load_keys(id_b, "", &after), MW_OK);
    CHECK_EQ_MEM(&after.sec, &before.sec, sizeof before.sec);
    CHECK_EQ_INT(mw_address_from_keys(&after, MW_NET_MAINNET, &addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&addr, addr_after, sizeof addr_after), MW_OK);
    CHECK_EQ_STR(addr_after, addr_before);

    // ... and after a power cycle with the NEW password.
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);           // reload from storage
    memset(&after, 0xcc, sizeof after);
    CHECK_EQ_INT(mw_wallet_load_keys(id_a, "", &after), MW_ERR_NOT_SUPPORTED); // no key
    CHECK_EQ_INT(mw_device_auth_verify("first-pw"), MW_ERR_DECRYPT);           // old one is dead
    CHECK_EQ_INT(mw_device_auth_verify("second-pw"), MW_OK);
    memset(&after, 0, sizeof after);
    CHECK_EQ_INT(mw_wallet_load_keys(id_b, "", &after), MW_OK);
    CHECK_EQ_MEM(&after.sec, &before.sec, sizeof before.sec);
    memset(&after, 0, sizeof after);
    CHECK_EQ_INT(mw_wallet_load_keys(id_a, "", &after), MW_OK);

    mw_memzero(&before, sizeof before);
    mw_memzero(&after, sizeof after);
}

MW_TEST(test_erase_and_reset)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("erase-me-1"), MW_OK);
    CHECK(mw_device_auth_is_set());
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
    // The record alone gone, with user files left: damaged, not "no password".
    CHECK(mw_device_auth_state() == MW_AUTH_CORRUPT);
    CHECK_EQ_INT(mw_fstore_wipe_all(), MW_OK);      // the rest of a factory reset
    CHECK(!mw_device_auth_is_set());
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK(!mw_device_auth_is_set());
    // A fresh password can be set again afterwards.
    CHECK_EQ_INT(mw_device_auth_set("erase-me-2"), MW_OK);
    CHECK(mw_device_auth_is_set());
}

// ---------------------------------------------------------------------------
// v5 bug 7: the failed-attempt counter after a correct password.
// ---------------------------------------------------------------------------

// The counter byte as storage holds it; -1 when there is no record.
static int stored_fails(void)
{
    uint8_t b[MW_DEVICE_AUTH_REC_LEN];
    size_t  len = 0;
    if (mw_store_blob_read("devauth", b, sizeof b, &len) != MW_OK ||
        len != MW_DEVICE_AUTH_REC_LEN) return -1;
    return b[57];
}

MW_TEST(test_success_reset_persists)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();

    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-2"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(stored_fails(), 2);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK(!mw_device_auth_save_pending());

    // Reboot: still 0, no delay; the next typo is attempt 1.
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-3"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);
}

MW_TEST(test_lockout_then_success_persists)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    for (int i = 0; i < 5; i++) {
        mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
        CHECK_EQ_INT(mw_device_auth_verify("wrong"), MW_ERR_DECRYPT);
    }
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 5);
    CHECK(mw_device_auth_lockout_ms() > 0u);
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);

    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
    CHECK_EQ_INT(stored_fails(), 0);
}

MW_TEST(test_reset_write_failure_retried)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-2"), MW_ERR_DECRYPT);

    // The attempt write and the reset write fail: the unlock still succeeds,
    // the write is pending.
    mw_host_store_fail_writes("devauth", 2);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK(mw_secure_user_key_present());
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(stored_fails(), 2);
    CHECK(mw_device_auth_save_pending());
    // A getter never writes.
    (void)mw_device_auth_lockout_ms();
    CHECK_EQ_INT(stored_fails(), 2);

    // Lock retries it.
    mw_device_auth_forget();
    CHECK(!mw_device_auth_save_pending());
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
}

MW_TEST(test_stale_storage_healed)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-2"), MW_ERR_DECRYPT);

    // Five failed writes: attempt + reset of the first verify(), then the
    // retry at the top of the next one and its attempt + reset.
    mw_host_store_fail_writes("devauth", 5);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);   // both fail again
    CHECK_EQ_INT(stored_fails(), 2);
    CHECK(mw_device_auth_save_pending());

    // Storage recovers: the next success writes the reset.
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK(!mw_device_auth_save_pending());

    // Storage changed behind the RAM copy (RAM 0, storage 2): a success
    // still rewrites it because the guard reads storage.
    {
        uint8_t b[MW_DEVICE_AUTH_REC_LEN];
        size_t  len = 0;
        CHECK_EQ_INT(mw_store_blob_read("devauth", b, sizeof b, &len), MW_OK);
        b[57] = 2;
        CHECK_EQ_INT(mw_store_blob_write("devauth", b, len), MW_OK);
    }
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
}

MW_TEST(test_increment_write_checked)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();

    mw_host_store_fail_writes("devauth", 1);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK(mw_device_auth_save_pending());

    // The next attempt first writes the pending count, then its own.
    CHECK_EQ_INT(mw_device_auth_verify("wrong-2"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(stored_fails(), 2);
    CHECK(!mw_device_auth_save_pending());
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 2);
}

MW_TEST(test_empty_input_not_counted)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();

    CHECK_EQ_INT(mw_device_auth_verify(""), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_device_auth_verify(NULL), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
    CHECK_EQ_INT(stored_fails(), 0);
    CHECK(!mw_secure_user_key_present());

    // Short but non-empty input is an attempt (no length rule in verify).
    CHECK_EQ_INT(mw_device_auth_verify("go"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);
}

MW_TEST(test_change_rekey_error_not_wrong_password)
{
    static wallet_store_t st;
    uint8_t  seed[32];
    uint32_t id = 0;

    fresh();
    CHECK_EQ_INT(mw_device_auth_set("good-pw"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    memset(seed, 0x33, sizeof seed);
    CHECK_EQ_INT(mw_wallet_create("C", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);

    // Damage the sealed record: it no longer unseals under any key.
    memset(&st, 0, sizeof st);
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK(st.count >= 1);
    st.wallets[0].seed_tag[0] ^= 0x01;
    CHECK_EQ_INT(mw_wallet_store_save(&st), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);

    const mw_err_t e = mw_device_auth_change("good-pw", "new-pw-1");
    CHECK(e != MW_OK);
    CHECK(e != MW_ERR_DECRYPT);
    CHECK_EQ_INT(e, MW_ERR_FORMAT);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);

    // Old password still valid, new one not.
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_verify("new-pw-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("good-pw"), MW_OK);
    mw_memzero(&st, sizeof st);
}

MW_TEST(test_erase_clears_pending)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    mw_host_store_fail_writes("devauth", 1);
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK(mw_device_auth_save_pending());

    // A factory reset must not let a pending retry resurrect the record.
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
    CHECK_EQ_INT(mw_fstore_wipe_all(), MW_OK);
    CHECK(!mw_device_auth_save_pending());
    mw_device_auth_forget();
    CHECK_EQ_INT(stored_fails(), -1);
    CHECK(!mw_device_auth_is_set());
}

MW_TEST(test_unreadable_storage_does_not_block_unlock)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);   // RAM 0, stored 0
    {
        uint8_t b[MW_DEVICE_AUTH_REC_LEN];
        size_t  len = 0;
        CHECK_EQ_INT(mw_store_blob_read("devauth", b, sizeof b, &len), MW_OK);
        b[57] = 2;                                  // storage behind RAM's back
        CHECK_EQ_INT(mw_store_blob_write("devauth", b, len), MW_OK);
    }

    // The stored-counter check cannot read storage: the unlock still works
    // and the reset is written anyway.
    mw_host_store_fail_reads("devauth", 1);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    mw_host_store_fail_reads("devauth", 0);
    CHECK_EQ_INT(stored_fails(), 0);
}

// ---------------------------------------------------------------------------
// Audit round 1: atomic change, verifier bound to the chip, counter before
// the check, damaged / missing record, upgrade of old records.
// ---------------------------------------------------------------------------
static int read_blob(const char* key, uint8_t* b, size_t cap)
{
    size_t len = 0;
    if (mw_store_blob_read(key, b, cap, &len) != MW_OK) return -1;
    return (int)len;
}

// Creates one wallet and returns its spend key (to compare after a reboot).
static uint32_t make_wallet(mw_seckey_t* spend_out)
{
    uint8_t seed[32];
    uint32_t id = 0;
    mw_account_keys_t k;
    memset(seed, 0x77, sizeof seed);
    CHECK_EQ_INT(mw_wallet_create("W", MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);
    memset(&k, 0, sizeof k);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &k), MW_OK);
    *spend_out = k.sec.spend;
    mw_memzero(&k, sizeof k);
    return id;
}

// A power cut: RAM is lost, nothing pending gets written (forget() would
// flush a pending record write, which a cut does not).
static void reboot(void)
{
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    (void)mw_device_auth_init();
}

static void expect_wallet(uint32_t id, const mw_seckey_t* spend)
{
    mw_account_keys_t k;
    memset(&k, 0, sizeof k);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &k), MW_OK);
    CHECK_EQ_MEM(k.sec.spend.b, spend->b, 32);
    mw_memzero(&k, sizeof k);
}

// Power lost after the wallets were re-keyed but before the final record
// write: either password completes the change.
MW_TEST(test_change_interrupted_after_rekey)
{
    static uint8_t rec[MW_DEVICE_AUTH_REC_LEN];
    mw_seckey_t spend;
    for (int which = 0; which < 2; ++which) {
        fresh();
        CHECK_EQ_INT(mw_device_auth_set("old-pass"), MW_OK);
        const uint32_t id = make_wallet(&spend);

        // devauth writes inside change(): attempt, reset (both from the
        // verify of the old password), pending record, final record. Let
        // three through and lose the final one.
        mw_host_store_fail_writes_after("devauth", 3, 1);
        CHECK_EQ_INT(mw_device_auth_change("old-pass", "new-pass"), MW_OK);
        CHECK(read_blob("devauth", rec, sizeof rec) == MW_DEVICE_AUTH_REC_LEN);
        CHECK(rec[58] & 0x02);                         // still "changing" in storage

        reboot();
        CHECK_EQ_INT(mw_device_auth_state(), MW_AUTH_SET);
        CHECK_EQ_INT(mw_device_auth_verify(which ? "new-pass" : "old-pass"), MW_OK);
        expect_wallet(id, &spend);
        CHECK(read_blob("devauth", rec, sizeof rec) == MW_DEVICE_AUTH_REC_LEN);
        CHECK(!(rec[58] & 0x02));                      // change completed

        // From now on only the new password works.
        reboot();
        CHECK_EQ_INT(mw_device_auth_verify("old-pass"), MW_ERR_DECRYPT);
        CHECK_EQ_INT(mw_device_auth_verify("new-pass"), MW_OK);
        expect_wallet(id, &spend);
    }
}

// Power lost after the pending record was written but before the wallet
// directory was re-sealed (it is still under the old key).
// Every user directory / decoy file, to put the file store back as it was.
#define SNAP_MAX 48
static char    g_snap_names[SNAP_MAX][MW_FSTORE_NAME_MAX + 1];
static uint8_t g_snap_data[SNAP_MAX][12 * 1024];
static size_t  g_snap_len[SNAP_MAX];
static int     g_snap_n;

static void files_snapshot(void)
{
    g_snap_n = mw_fstore_list("u", g_snap_names, SNAP_MAX);
    for (int i = 0; i < g_snap_n; i++) {
        CHECK_EQ_INT(mw_fstore_read(g_snap_names[i], g_snap_data[i], sizeof g_snap_data[i],
                                    &g_snap_len[i]), MW_OK);
    }
}

static void files_restore(void)
{
    static char now[SNAP_MAX][MW_FSTORE_NAME_MAX + 1];
    const int n = mw_fstore_list("u", now, SNAP_MAX);
    for (int i = 0; i < n; i++) (void)mw_fstore_remove(now[i]);
    for (int i = 0; i < g_snap_n; i++)
        CHECK_EQ_INT(mw_fstore_write(g_snap_names[i], g_snap_data[i], g_snap_len[i]), MW_OK);
}

// Power lost after the pending record was written but before the wallet
// directory was re-sealed (it is still under the old key).
MW_TEST(test_change_interrupted_before_rekey)
{
    mw_seckey_t spend;
    for (int which = 0; which < 2; ++which) {
        fresh();
        CHECK_EQ_INT(mw_device_auth_set("old-pass"), MW_OK);
        const uint32_t id = make_wallet(&spend);
        files_snapshot();
        CHECK(g_snap_n >= 4);

        mw_host_store_fail_writes_after("devauth", 3, 1);   // final write lost
        CHECK_EQ_INT(mw_device_auth_change("old-pass", "new-pass"), MW_OK);
        // ... and the re-sealed directory never reached storage either.
        files_restore();

        reboot();
        CHECK_EQ_INT(mw_device_auth_verify(which ? "new-pass" : "old-pass"), MW_OK);
        expect_wallet(id, &spend);
        reboot();
        CHECK_EQ_INT(mw_device_auth_verify("new-pass"), MW_OK);
        expect_wallet(id, &spend);
        CHECK_EQ_INT(mw_device_auth_verify("old-pass"), MW_ERR_DECRYPT);
    }
}

// The verifier and the key depend on the eFuse key: the same record under a
// different chip key does not accept the right password.
MW_TEST(test_verifier_bound_to_chip)
{
    uint8_t other[32];
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("chip-pass"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("chip-pass"), MW_OK);
    mw_device_auth_forget();

    memset(other, 0x5c, sizeof other);
    CHECK_EQ_INT(mw_store_blob_write("efuse_hmac_key0.bin", other, sizeof other), MW_OK);
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_verify("chip-pass"), MW_ERR_DECRYPT);
}

// The attempt is in storage before the check finishes: the counter written
// by verify() already holds the attempt when the derivation runs. Seen from
// outside: a wrong password whose LAST write fails still left the raised
// counter in storage (the raise is the first write).
MW_TEST(test_attempt_counted_before_check)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("right-pw"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("wrong-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(stored_fails(), 1);
    // A correct password: raised (2) then cleared (0). Fail the clear: the
    // raised value is what a power cut at that moment leaves behind.
    mw_host_store_fail_writes_after("devauth", 1, 1);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(stored_fails(), 2);
}

MW_TEST(test_damaged_record_not_overwritten)
{
    mw_seckey_t spend;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("keep-me"), MW_OK);
    (void)make_wallet(&spend);

    // Garbage record.
    const uint8_t junk[20] = { 'M', 'W', 'D', 'X' };
    CHECK_EQ_INT(mw_store_blob_write("devauth", junk, sizeof junk), MW_OK);
    reboot();
    CHECK_EQ_INT(mw_device_auth_state(), MW_AUTH_CORRUPT);
    CHECK(mw_device_auth_is_set());
    CHECK(mw_device_auth_set("new-one") != MW_OK);

    // Record gone altogether, wallets still there.
    CHECK_EQ_INT(mw_store_blob_erase("devauth"), MW_OK);
    reboot();
    CHECK_EQ_INT(mw_device_auth_state(), MW_AUTH_CORRUPT);
    CHECK(mw_device_auth_is_set());
    CHECK_EQ_INT(mw_device_auth_set("new-one"), MW_ERR_FORMAT);
    CHECK(read_blob("devauth", (uint8_t[8]){0}, 8) < 0);   // nothing written
}

// A version-1 record (20000 rounds, no chip binding) still unlocks and is
// upgraded on the way; the wallets follow.
MW_TEST(test_v1_record_upgraded)
{
    static const char tag[] = "mw.device.pw.v1";
    static const char vtag[] = "mw.device.verify";
    uint8_t salt[16 + sizeof tag - 1], out[64], key[32], rec[58], buf[MW_DEVICE_AUTH_REC_LEN];
    mw_seckey_t spend;

    fresh();
    memset(salt, 0x11, 16);
    memcpy(salt + 16, tag, sizeof tag - 1);
    mw_pbkdf2_sha512((const uint8_t*)"legacy-pw", 9, salt, sizeof salt, 20000, out, 64);
    memcpy(key, out, 32);
    memset(rec, 0, sizeof rec);
    rec[0] = 'M'; rec[1] = 'W'; rec[2] = 'D'; rec[3] = 'A'; rec[4] = 1;
    rec[5] = 0x20; rec[6] = 0x4E;                         // 20000
    memset(rec + 9, 0x11, 16);
    mw_hmac_sha256(out + 32, 32, (const uint8_t*)vtag, sizeof vtag - 1, rec + 25);
    CHECK_EQ_INT(mw_store_blob_write("devauth", rec, sizeof rec), MW_OK);
    // A wallet sealed under the version-1 key.
    CHECK_EQ_INT(mw_secure_user_key_set(key), MW_OK);
    const uint32_t id = make_wallet(&spend);

    reboot();
    CHECK_EQ_INT(mw_device_auth_state(), MW_AUTH_SET);
    CHECK_EQ_INT(mw_device_auth_verify("wrong"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("legacy-pw"), MW_OK);
    expect_wallet(id, &spend);
    CHECK_EQ_INT(read_blob("devauth", buf, sizeof buf), MW_DEVICE_AUTH_REC_LEN);
    CHECK_EQ_INT(buf[4], 2);
    CHECK_EQ_INT(buf[5] | (buf[6] << 8) | (buf[7] << 16), MW_DEVICE_PW_ROUNDS);
    CHECK(buf[58] & 0x01);                                   // bound to the chip now

    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("legacy-pw"), MW_OK);
    expect_wallet(id, &spend);
    mw_memzero(key, sizeof key);
    mw_memzero(out, sizeof out);
}

// A password set before the eFuse key was provisioned is bound to the chip
// at the first unlock after provisioning.
MW_TEST(test_unbound_record_bound_after_provisioning)
{
    uint8_t buf[MW_DEVICE_AUTH_REC_LEN];
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
    CHECK(mw_secure_key_status() != MW_OK);

    CHECK_EQ_INT(mw_device_auth_set("early-pw"), MW_OK);
    CHECK_EQ_INT(read_blob("devauth", buf, sizeof buf), MW_DEVICE_AUTH_REC_LEN);
    CHECK(!(buf[58] & 0x01));

    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("early-pw"), MW_OK);
    CHECK_EQ_INT(read_blob("devauth", buf, sizeof buf), MW_DEVICE_AUTH_REC_LEN);
    CHECK(buf[58] & 0x01);
    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("early-pw"), MW_OK);
}

// The slow parts report progress: monotonic within a stage, reaching the
// end, with the stages the operation goes through.
static int g_pstage[16], g_pmax[16], g_pbad;
static void prog_cb(int stage, int pm, void* ctx)
{
    (void)ctx;
    if (stage < 0 || stage >= 16 || pm < 0 || pm > 1000) { g_pbad++; return; }
    if (g_pstage[stage] && pm < g_pmax[stage]) g_pbad++;   // went backwards
    g_pstage[stage] = 1;
    if (pm > g_pmax[stage]) g_pmax[stage] = pm;
}

MW_TEST(test_progress_reported)
{
    mw_seckey_t spend;
    fresh();
    memset(g_pstage, 0, sizeof g_pstage); memset(g_pmax, 0, sizeof g_pmax); g_pbad = 0;
    mw_device_auth_set_progress(prog_cb, NULL);
    CHECK_EQ_INT(mw_device_auth_set("progress-pw"), MW_OK);
    CHECK(g_pstage[MW_AUTH_STAGE_NEW]);
    CHECK_EQ_INT(g_pmax[MW_AUTH_STAGE_NEW], 1000);
    (void)make_wallet(&spend);

    reboot();
    memset(g_pstage, 0, sizeof g_pstage); memset(g_pmax, 0, sizeof g_pmax);
    CHECK_EQ_INT(mw_device_auth_verify("progress-pw"), MW_OK);
    CHECK(g_pstage[MW_AUTH_STAGE_CHECK]);
    CHECK(g_pmax[MW_AUTH_STAGE_CHECK] >= 990);            // 1024-iteration ticks
    CHECK(!g_pstage[MW_AUTH_STAGE_UPGRADE]);               // already current

    memset(g_pstage, 0, sizeof g_pstage); memset(g_pmax, 0, sizeof g_pmax);
    CHECK_EQ_INT(mw_device_auth_change("progress-pw", "progress-2"), MW_OK);
    CHECK(g_pstage[MW_AUTH_STAGE_CHECK] && g_pstage[MW_AUTH_STAGE_NEW] &&
          g_pstage[MW_AUTH_STAGE_REKEY]);
    CHECK_EQ_INT(g_pmax[MW_AUTH_STAGE_REKEY], 1000);
    CHECK_EQ_INT(g_pbad, 0);
    mw_device_auth_set_progress(NULL, NULL);
}

MW_TEST(test_weak_passwords)
{
    CHECK(mw_device_pw_weak("12345678"));
    CHECK(mw_device_pw_weak("00000000"));
    CHECK(mw_device_pw_weak("aaaaaaaa"));
    CHECK(mw_device_pw_weak("abcdefgh"));
    CHECK(mw_device_pw_weak("hgfedcba"));
    CHECK(mw_device_pw_weak("90210777"));
    CHECK(mw_device_pw_weak(""));
    CHECK(!mw_device_pw_weak("correct horse"));
    CHECK(!mw_device_pw_weak("abcdefgx"));
    CHECK(!mw_device_pw_weak("Tr0ub4dor"));
}

int main(void)
{
    mw_random_init();
    (void)mw_hal_init();

    RUN_TEST(test_no_password_yet);
    RUN_TEST(test_set_rules_and_verify);
    RUN_TEST(test_lockout_after_failures);
    RUN_TEST(test_change_password_rekeys_wallets);
    RUN_TEST(test_erase_and_reset);
    RUN_TEST(test_success_reset_persists);
    RUN_TEST(test_lockout_then_success_persists);
    RUN_TEST(test_reset_write_failure_retried);
    RUN_TEST(test_stale_storage_healed);
    RUN_TEST(test_increment_write_checked);
    RUN_TEST(test_empty_input_not_counted);
    RUN_TEST(test_change_rekey_error_not_wrong_password);
    RUN_TEST(test_erase_clears_pending);
    RUN_TEST(test_unreadable_storage_does_not_block_unlock);
    RUN_TEST(test_change_interrupted_after_rekey);
    RUN_TEST(test_change_interrupted_before_rekey);
    RUN_TEST(test_verifier_bound_to_chip);
    RUN_TEST(test_attempt_counted_before_check);
    RUN_TEST(test_damaged_record_not_overwritten);
    RUN_TEST(test_v1_record_upgraded);
    RUN_TEST(test_unbound_record_bound_after_provisioning);
    RUN_TEST(test_progress_reported);

    mw_secure_user_key_clear();
    mw_host_store_reset();
    RUN_TEST(test_weak_passwords);
    return mw_test_summary();
}
