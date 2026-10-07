// Session state, autolock and buffer wiping (TZ 5.2, 5.10, 8.1).
//
// Build (host):
//   gcc -std=c11 -Wall -Wextra -O2 -I../src -I. -DMW_HOST_BUILD=1
//       test_session.c ../src/wallet/*.c ../src/crypto/*.c
//       ../src/monero/*.c ../src/data/*.c test_framework.c -o /tmp/t_sess && /tmp/t_sess

#include "test_framework.h"

#include "crypto/memzero.h"
#include "crypto/random.h"
#include "monero/mnemonic.h"
#include "wallet/secure_storage.h"
#include "wallet/session.h"
#include "wallet/wallet_store.h"

// Host-backend / host-clock test hooks (not part of the frozen API).
void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);
void mw_settings_test_set_display(int has_touch, int width, int height);
void mw_session_test_set_time_ms(uint32_t ms);
void mw_session_test_advance_ms(uint32_t ms);

#define STORE_DIR "./.mw_test_session_store"

static uint32_t g_wallet_id;
static uint8_t  g_seed[32];

// task2 item 1: sealing needs the user password key next to the eFuse key.
static const uint8_t TEST_USER_KEY[32] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
};

static void fresh_device(uint16_t autolock_min)
{
    mw_settings_t s;
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 240, 320);

    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_secure_user_key_set(TEST_USER_KEY), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);

    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    s.autolock_min = autolock_min;
    CHECK_EQ_INT(mw_settings_save(&s), MW_OK);

    for (size_t i = 0; i < sizeof g_seed; i++) g_seed[i] = (uint8_t)(i * 9u + 3u);
    g_wallet_id = 0;
    CHECK_EQ_INT(mw_wallet_create("Session", MW_SEED_MONERO_LEGACY, g_seed,
                                  sizeof g_seed, 0u, &g_wallet_id), MW_OK);

    mw_session_test_set_time_ms(1000u);
    mw_session_lock();
}

MW_TEST(test_session_starts_locked)
{
    fresh_device(5);
    mw_session_lock();
    CHECK_EQ_INT(mw_session()->unlocked, 0);
    CHECK_EQ_INT(mw_session()->wallet_id, 0u);
    CHECK(mw_ct_is_zero(&mw_session()->keys, sizeof mw_session()->keys));
    // A locked session always reports "expired" so callers cannot use it.
    CHECK_EQ_INT(mw_session_expired(), 1);
}

MW_TEST(test_session_unlock_and_lock)
{
    mw_account_keys_t expected;
    fresh_device(5);

    memset(&expected, 0, sizeof expected);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, g_seed, sizeof g_seed,
                                 "pass phrase", &expected), MW_OK);

    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, "pass phrase"), MW_OK);
    CHECK_EQ_INT(mw_session()->unlocked, 1);
    CHECK_EQ_INT(mw_session()->wallet_id, g_wallet_id);
    CHECK_EQ_MEM(&mw_session()->keys.sec, &expected.sec, sizeof expected.sec);
    CHECK_EQ_MEM(&mw_session()->keys.pub, &expected.pub, sizeof expected.pub);
    CHECK_EQ_INT(mw_session_expired(), 0);

    // TZ 8.1: locking wipes the key material, not just the flag.
    mw_session_lock();
    CHECK_EQ_INT(mw_session()->unlocked, 0);
    CHECK_EQ_INT(mw_session()->wallet_id, 0u);
    CHECK(mw_ct_is_zero(&mw_session()->keys, sizeof mw_session()->keys));
}

MW_TEST(test_session_unlock_failure_leaves_locked)
{
    fresh_device(5);
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id + 99u, ""), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_session()->unlocked, 0);
    CHECK(mw_ct_is_zero(&mw_session()->keys, sizeof mw_session()->keys));

    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, NULL), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_session()->unlocked, 0);

    // A successful unlock followed by a failing one must not leave stale keys.
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, ""), MW_OK);
    CHECK_EQ_INT(mw_session()->unlocked, 1);
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id + 99u, ""), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_session()->unlocked, 0);
    CHECK(mw_ct_is_zero(&mw_session()->keys, sizeof mw_session()->keys));
}

MW_TEST(test_session_autolock_timeout)
{
    fresh_device(5);                       // 5 minutes
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, ""), MW_OK);
    CHECK_EQ_INT(mw_session_expired(), 0);

    mw_session_test_advance_ms(4u * 60u * 1000u);
    CHECK_EQ_INT(mw_session_expired(), 0);

    // Activity restarts the clock (TZ 4.2 auto-lock).
    mw_session_touch();
    mw_session_test_advance_ms(4u * 60u * 1000u);
    CHECK_EQ_INT(mw_session_expired(), 0);

    mw_session_test_advance_ms(1u * 60u * 1000u);   // exactly at the timeout
    CHECK_EQ_INT(mw_session_expired(), 1);

    mw_session_test_advance_ms(60u * 1000u);
    CHECK_EQ_INT(mw_session_expired(), 1);
}

MW_TEST(test_session_autolock_zero_means_never)
{
    fresh_device(0);
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, ""), MW_OK);
    mw_session_test_advance_ms(24u * 60u * 60u * 1000u);
    CHECK_EQ_INT(mw_session_expired(), 0);
    mw_session_lock();
    CHECK_EQ_INT(mw_session_expired(), 1);
}

MW_TEST(test_session_autolock_survives_millis_wraparound)
{
    fresh_device(5);
    // mw_millis() wraps every ~49.7 days; unsigned arithmetic must absorb it.
    mw_session_test_set_time_ms(0xfffff000u);
    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, ""), MW_OK);
    mw_session_test_advance_ms(0x2000u);            // wraps past 0
    CHECK_EQ_INT(mw_session_expired(), 0);
    mw_session_test_advance_ms(5u * 60u * 1000u);
    CHECK_EQ_INT(mw_session_expired(), 1);
}

MW_TEST(test_session_input_buffer)
{
    size_t cap = 0;
    char* buf = mw_session_input_buffer(&cap);

    fresh_device(5);
    buf = mw_session_input_buffer(&cap);
    CHECK(buf != NULL);
    // TZ 5.9: passphrases are not bounded by a wordlist, so the buffer has to
    // be roomy. 256 bytes is the project's floor.
    CHECK(cap >= 256u);
    // Stable across calls - it is one fixed static buffer.
    CHECK(mw_session_input_buffer(NULL) == buf);

    memset(buf, 'A', cap - 1);
    buf[cap - 1] = '\0';
    CHECK(!mw_ct_is_zero(buf, cap));

    mw_session_wipe_input();
    CHECK(mw_ct_is_zero(buf, cap));

    // mw_session_lock() must wipe the typed passphrase too (TZ 5.2).
    memset(buf, 'B', cap - 1);
    mw_session_lock();
    CHECK(mw_ct_is_zero(buf, cap));
}

MW_TEST(test_session_network_from_settings)
{
    mw_settings_t s;
    fresh_device(5);
    CHECK_EQ_INT(mw_settings_load(&s), MW_OK);
    s.network = MW_NET_STAGENET;
    CHECK_EQ_INT(mw_settings_save(&s), MW_OK);

    CHECK_EQ_INT(mw_session_unlock(g_wallet_id, ""), MW_OK);
    CHECK_EQ_INT(mw_session()->network, MW_NET_STAGENET);
}

int main(void)
{
    mw_random_init();

    RUN_TEST(test_session_starts_locked);
    RUN_TEST(test_session_unlock_and_lock);
    RUN_TEST(test_session_unlock_failure_leaves_locked);
    RUN_TEST(test_session_autolock_timeout);
    RUN_TEST(test_session_autolock_zero_means_never);
    RUN_TEST(test_session_autolock_survives_millis_wraparound);
    RUN_TEST(test_session_input_buffer);
    RUN_TEST(test_session_network_from_settings);

    mw_session_lock();
    mw_host_store_reset();
    return mw_test_summary();
}
