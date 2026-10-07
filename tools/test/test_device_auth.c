// Device password (task2 item 1): set / verify / lockout / change + rekey,
// and the rule that nothing seals without the user key.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"

#include "crypto/memzero.h"
#include "crypto/random.h"
#include "monero/address.h"
#include "monero/mnemonic.h"
#include "wallet/device_auth.h"
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
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);

#define STORE_DIR "./.mw_test_devauth_store"

static void fresh(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 240, 320);
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
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
    uint8_t b[64];
    size_t  len = 0;
    if (mw_store_blob_read("devauth", b, sizeof b, &len) != MW_OK || len != 58) return -1;
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

    // The reset write fails: the unlock still succeeds, the write is pending.
    mw_host_store_fail_writes("devauth", 1);
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

    // Three failed writes: the reset, then the retry at the top of the next
    // verify() and that verify's own reset.
    mw_host_store_fail_writes("devauth", 3);
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
        uint8_t b[64];
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
        uint8_t b[64];
        size_t  len = 0;
        CHECK_EQ_INT(mw_store_blob_read("devauth", b, sizeof b, &len), MW_OK);
        b[57] = 2;                                  // storage behind RAM's back
        CHECK_EQ_INT(mw_store_blob_write("devauth", b, len), MW_OK);
    }

    // The stored-counter check cannot read storage: the unlock still works
    // and the reset is written anyway.
    mw_host_store_fail_reads("devauth", 1);
    CHECK_EQ_INT(mw_device_auth_verify("right-pw"), MW_OK);
    CHECK_EQ_INT(stored_fails(), 0);
    mw_host_store_fail_reads("devauth", 0);
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

    mw_secure_user_key_clear();
    mw_host_store_reset();
    return mw_test_summary();
}
