// Users with their own passwords (v9): isolation, add / delete / change,
// interrupted changes, the decoy files and the move of a pre-v9 directory.
#include "test_framework.h"

#include "crypto/memzero.h"
#include "wallet/device_auth.h"
#include "wallet/file_store.h"
#include "wallet/ki_cache.h"
#include "wallet/secure_storage.h"
#include "wallet/wallet_store.h"

#include <stdio.h>
#include <string.h>

void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);
void mw_host_advance_ms(uint32_t ms);
void mw_settings_test_set_display(int has_touch, int w, int h);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_host_wallet_store_write_legacy(const wallet_store_t* s, uint32_t next_id);
void mw_host_wallet_store_stop_after_commit(void);

#define STORE_DIR "./.mw_test_users_store"

static void fresh(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    mw_settings_test_set_display(1, 240, 320);
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_erase(), MW_OK);
    CHECK_EQ_INT(mw_fstore_wipe_all(), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_device_auth_init(), MW_OK);
}

// Logs in, skipping any lockout delay left by a deliberate wrong guess.
static mw_err_t login(const char* pw)
{
    mw_device_auth_forget();
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    return mw_device_auth_verify(pw);
}

static void reboot(void)
{
    mw_secure_user_key_clear();
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    (void)mw_device_auth_init();
}

static uint32_t make_wallet(const char* name, uint8_t fill, mw_seckey_t* spend)
{
    uint8_t seed[32];
    uint32_t id = 0;
    mw_account_keys_t k;
    memset(seed, fill, sizeof seed);
    CHECK_EQ_INT(mw_wallet_create(name, MW_SEED_MONERO_LEGACY, seed, 32, 0, &id), MW_OK);
    memset(&k, 0, sizeof k);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &k), MW_OK);
    if (spend) *spend = k.sec.spend;
    mw_memzero(&k, sizeof k);
    return id;
}

static uint32_t wallet_count(void)
{
    uint32_t n = 999;
    CHECK_EQ_INT(mw_wallet_store_count(&n), MW_OK);
    return n;
}

static void expect_only(const char* name, const mw_seckey_t* spend)
{
    static wallet_store_t st;
    mw_account_keys_t k;
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT((int)st.count, 1);
    CHECK_EQ_STR(st.wallets[0].name, name);
    memset(&k, 0, sizeof k);
    CHECK_EQ_INT(mw_wallet_load_keys(st.wallets[0].id, "", &k), MW_OK);
    CHECK_EQ_MEM(k.sec.spend.b, spend->b, 32);
    mw_memzero(&k, sizeof k);
    mw_memzero(&st, sizeof st);
}

// Every directory file (users and decoys) has the same size.
static int user_files_same_size(void)
{
    static char names[64][MW_FSTORE_NAME_MAX + 1];
    const int n = mw_fstore_list("u", names, 64);
    size_t first = 0;
    for (int i = 0; i < n && i < 64; i++) {
        size_t len = 0;
        if (mw_fstore_size(names[i], &len) != MW_OK) return -1;
        if (i == 0) first = len;
        else if (len != first) return -1;
    }
    return n;
}

MW_TEST(test_users_are_isolated)
{
    mw_seckey_t sa, sb;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    const int files0 = user_files_same_size();
    CHECK_EQ_INT(files0, MW_USER_FILES_MAX);       // every slot, from the start
    make_wallet("Alpha", 0x11, &sa);
    CHECK(mw_device_auth_users_possible());
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(user_files_same_size(), files0);  // a decoy gave way
    // The adding user stays logged in and still sees only its own wallet.
    expect_only("Alpha", &sa);

    CHECK_EQ_INT(login("second-password"), MW_OK);
    CHECK_EQ_INT((int)wallet_count(), 0);
    make_wallet("Beta", 0x22, &sb);
    expect_only("Beta", &sb);

    CHECK_EQ_INT(login("first-password"), MW_OK);
    expect_only("Alpha", &sa);
    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("second-password"), MW_OK);
    expect_only("Beta", &sb);
    CHECK_EQ_INT(login("nobody-password"), MW_ERR_DECRYPT);
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(user_files_same_size(), files0);
}

MW_TEST(test_add_user_rules)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("first-password", NULL), MW_ERR_EXISTS);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 1);     // costs a guess
    CHECK_EQ_INT(mw_device_auth_add_user("short", NULL), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_ERR_EXISTS);
    CHECK_EQ_INT(mw_device_auth_add_user("x-password-1", NULL), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_ERR_EXISTS);
    CHECK(mw_device_auth_lockout_ms() > 0);                // three guesses
    CHECK_EQ_INT(mw_device_auth_add_user("y-password", NULL), MW_ERR_ABORTED);
    // From the other user too: the taken password is refused either way.
    CHECK_EQ_INT(login("second-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("first-password", NULL), MW_ERR_EXISTS);
    CHECK_EQ_INT(mw_device_auth_add_user("third-password", NULL), MW_OK);
    CHECK_EQ_INT(login("third-password"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_add_user("fourth-password", NULL), MW_ERR_NOT_SUPPORTED);
}

MW_TEST(test_user_limit)
{
    char pw[32];
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    int added = 0;
    mw_err_t e = MW_OK;
    for (int i = 0; i < 64 && e == MW_OK; i++) {
        snprintf(pw, sizeof pw, "user-password-%02d", i);
        e = mw_device_auth_add_user(pw, NULL);
        if (e == MW_OK) added++;
    }
    CHECK_EQ_INT(e, MW_ERR_TOO_MANY);
    CHECK_EQ_INT(added + 1, MW_USERS_MAX);         // the first user counts too
    CHECK_EQ_INT(user_files_same_size(), MW_USER_FILES_MAX);
    CHECK_EQ_INT(login("user-password-00"), MW_OK);
}

MW_TEST(test_delete_other_user)
{
    mw_seckey_t sa;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, &sa);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    const int files = user_files_same_size();
    CHECK_EQ_INT(login("second-password"), MW_OK);
    make_wallet("Beta", 0x22, NULL);
    // Only its own password deletes it, and nobody else's.
    CHECK_EQ_INT(mw_device_auth_delete_user("first-password"), MW_ERR_DECRYPT);
    CHECK(mw_secure_user_key_present());
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    CHECK_EQ_INT(mw_device_auth_delete_user("second-password"), MW_OK);
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(user_files_same_size(), files);   // its slot is a decoy again
    CHECK_EQ_INT(login("second-password"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    expect_only("Alpha", &sa);
}

MW_TEST(test_delete_first_user)
{
    mw_seckey_t sb;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, NULL);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    make_wallet("Beta", 0x22, &sb);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_delete_user("first-password"), MW_OK);
    CHECK(mw_device_auth_is_set());                // the record stays
    CHECK_EQ_INT(login("first-password"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    expect_only("Beta", &sb);
    // The device keeps working for the remaining user.
    CHECK_EQ_INT(mw_device_auth_add_user("third-password", NULL), MW_OK);
    CHECK_EQ_INT(login("third-password"), MW_OK);
    CHECK_EQ_INT((int)wallet_count(), 0);
}

MW_TEST(test_change_other_user_password)
{
    mw_seckey_t sa, sb;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, &sa);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    const uint32_t id = make_wallet("Beta", 0x22, &sb);

    // A key image cache follows the wallet to the new key.
    mw_account_keys_t k;
    mw_ki_entry_t e;
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &k), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_open(id, 0, &k), MW_OK);
    memset(&e, 0, sizeof e);
    memset(e.out_pub.b, 0x5A, 32);
    memset(e.image.b, 0x6B, 32);
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    mw_ki_cache_close();

    CHECK_EQ_INT(mw_device_auth_change("second-password", "first-password"), MW_ERR_EXISTS);
    CHECK_EQ_INT(mw_device_auth_change("first-password", "whatever-new"), MW_ERR_DECRYPT);
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    CHECK_EQ_INT(mw_device_auth_change("second-password", "second-new-pw"), MW_OK);
    expect_only("Beta", &sb);
    CHECK_EQ_INT(login("second-password"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(login("second-new-pw"), MW_OK);
    expect_only("Beta", &sb);
    CHECK_EQ_INT(mw_ki_cache_open(id, 0, &k), MW_OK);
    CHECK_EQ_INT((int)mw_ki_cache_count(), 1);
    CHECK(!mw_ki_cache_rolled_back());
    mw_ki_cache_close();
    mw_memzero(&k, sizeof k);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    expect_only("Alpha", &sa);
}

// The first user's password change keeps the record's salt and rounds: the
// other users still open.
MW_TEST(test_first_user_change_keeps_others)
{
    mw_seckey_t sa, sb;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, &sa);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    make_wallet("Beta", 0x22, &sb);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_change("first-password", "second-password"), MW_ERR_EXISTS);
    CHECK_EQ_INT(mw_device_auth_change("first-password", "first-new-pw"), MW_OK);
    expect_only("Alpha", &sa);
    CHECK_EQ_INT(login("first-new-pw"), MW_OK);
    expect_only("Alpha", &sa);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    expect_only("Beta", &sb);
    CHECK_EQ_INT(login("first-password"), MW_ERR_DECRYPT);
}

// Power lost right after the new directory was written: either password
// finishes the change.
MW_TEST(test_other_user_change_interrupted)
{
    mw_seckey_t sb;
    for (int which = 0; which < 2; ++which) {
        fresh();
        CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
        CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
        CHECK_EQ_INT(login("second-password"), MW_OK);
        make_wallet("Beta", 0x22, &sb);
        const int files = user_files_same_size();
        mw_host_wallet_store_stop_after_commit();
        CHECK_EQ_INT(mw_device_auth_change("second-password", "second-new-pw"), MW_OK);
        CHECK_EQ_INT(user_files_same_size(), files + 1);   // both directories
        reboot();
        CHECK_EQ_INT(mw_device_auth_verify(which ? "second-new-pw" : "second-password"), MW_OK);
        expect_only("Beta", &sb);
        CHECK_EQ_INT(user_files_same_size(), files);
        CHECK_EQ_INT(login("second-new-pw"), MW_OK);
        expect_only("Beta", &sb);
        CHECK_EQ_INT(login("second-password"), MW_ERR_DECRYPT);
    }
}

// A device from before v9: the NVS directory and the old key image cache
// names move to the first user at its next unlock.
MW_TEST(test_legacy_directory_migrated)
{
    static wallet_store_t st;
    static uint8_t file[64 * 1024];
    mw_seckey_t sa;
    mw_account_keys_t k;
    mw_ki_entry_t e;
    char name[40], legacy[40];
    size_t len = 0;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    const uint32_t id = make_wallet("Alpha", 0x11, &sa);
    CHECK_EQ_INT(mw_wallet_load_keys(id, "", &k), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_open(id, 0, &k), MW_OK);
    memset(&e, 0, sizeof e);
    memset(e.out_pub.b, 0x5A, 32);
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    mw_ki_cache_close();

    // Rewrite the store the way firmware before v9 kept it.
    CHECK_EQ_INT(mw_wallet_store_load(&st), MW_OK);
    CHECK_EQ_INT(mw_host_wallet_store_write_legacy(&st, id + 1), MW_OK);
    mw_ki_cache_file_name(id, 0, name, sizeof name);
    snprintf(legacy, sizeof legacy, "ki_%08lx_0.bin", (unsigned long)id);
    CHECK_EQ_INT(mw_fstore_read(name, file, sizeof file, &len), MW_OK);
    CHECK_EQ_INT(mw_fstore_write(legacy, file, len), MW_OK);
    CHECK_EQ_INT(mw_fstore_remove(name), MW_OK);
    const uint8_t gen[4] = { 1, 0, 0, 0 };
    char gk[16];
    snprintf(gk, sizeof gk, "kig%08lx0", (unsigned long)id);
    CHECK_EQ_INT(mw_store_blob_write(gk, gen, 4), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_user_destroy(), MW_OK);   // drops the v9 directory
    {
        static char names[64][MW_FSTORE_NAME_MAX + 1];
        const int n = mw_fstore_list("u", names, 64);
        for (int i = 0; i < n; i++) (void)mw_fstore_remove(names[i]);
    }
    // ki_cache's file went with destroy(): put the legacy one back.
    CHECK_EQ_INT(mw_fstore_write(legacy, file, len), MW_OK);

    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("first-password"), MW_OK);
    expect_only("Alpha", &sa);
    CHECK(mw_store_blob_read("wallets", file, sizeof file, &len) != MW_OK);
    CHECK(mw_store_blob_read(gk, file, sizeof file, &len) != MW_OK);
    CHECK(mw_fstore_size(legacy, &len) != MW_OK);
    CHECK_EQ_INT(user_files_same_size(), MW_USER_FILES_MAX);
    CHECK_EQ_INT(mw_ki_cache_open(id, 0, &k), MW_OK);
    CHECK_EQ_INT((int)mw_ki_cache_count(), 1);
    CHECK(!mw_ki_cache_rolled_back());
    CHECK_EQ_INT((int)mw_wallet_ki_gen(id, 0), 1);
    mw_ki_cache_close();
    mw_memzero(&k, sizeof k);
}

// Wrong guesses of anyone count against the one shared counter.
MW_TEST(test_shared_attempt_counter)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("guess-1"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("guess-2"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_verify("guess-3"), MW_ERR_DECRYPT);
    CHECK(mw_device_auth_lockout_ms() > 0);
    CHECK_EQ_INT(mw_device_auth_verify("second-password"), MW_ERR_ABORTED);
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    CHECK_EQ_INT(mw_device_auth_verify("second-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_failed_attempts(), 0);
}

// Pre-v9 firmware wrote an empty NVS directory at every boot: finding one
// after v9 already holds wallets changes nothing.
MW_TEST(test_empty_legacy_blob_ignored)
{
    static wallet_store_t empty;
    static uint8_t buf[2048];
    size_t len = 0;
    mw_seckey_t sa;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, &sa);
    memset(&empty, 0, sizeof empty);
    CHECK_EQ_INT(mw_host_wallet_store_write_legacy(&empty, 1), MW_OK);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    expect_only("Alpha", &sa);
    CHECK(mw_store_blob_read("wallets", buf, sizeof buf, &len) != MW_OK);
}

// A power cut between "old file -> .bak" and ".tmp -> name": the next read
// puts the old copy back.
MW_TEST(test_directory_bak_recovered)
{
    static char names[64][MW_FSTORE_NAME_MAX + 1];
    char a[700], b[700];
    mw_seckey_t sb;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", NULL), MW_OK);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    make_wallet("Beta", 0x22, &sb);
    mw_device_auth_forget();
    const int n = mw_fstore_list("u", names, 64);
    for (int i = 0; i < n; i++) {
        snprintf(a, sizeof a, "%s/fs_%.32s", STORE_DIR, names[i]);
        snprintf(b, sizeof b, "%s/fs_%.32s.bak", STORE_DIR, names[i]);
        CHECK_EQ_INT(rename(a, b), 0);
    }
    CHECK_EQ_INT(mw_fstore_list("u", NULL, 0), 0);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    expect_only("Beta", &sb);
    CHECK_EQ_INT(login("first-password"), MW_OK);
}

// The first user's password change cut after its commit point: the old
// directory is left "superseded"; the old password must not open it as
// another user, the new one finishes the change.
MW_TEST(test_first_user_change_leftover)
{
    mw_seckey_t sa;
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    make_wallet("Alpha", 0x11, &sa);
    const int files = user_files_same_size();
    mw_host_wallet_store_stop_after_commit();
    CHECK_EQ_INT(mw_device_auth_change("first-password", "first-new-pw"), MW_OK);
    CHECK_EQ_INT(user_files_same_size(), files + 1);
    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("first-password"), MW_ERR_DECRYPT);
    CHECK(!mw_secure_user_key_present());
    CHECK_EQ_INT(login("first-new-pw"), MW_OK);
    expect_only("Alpha", &sa);
    CHECK_EQ_INT(user_files_same_size(), files);
    CHECK_EQ_INT(mw_device_auth_delete_user("first-new-pw"), MW_OK);
    CHECK_EQ_INT(login("first-password"), MW_ERR_DECRYPT);
}

// Knowing one password does not give unlimited guesses at another: logging
// in between the guesses does not clear the lifetime counter.
MW_TEST(test_guessing_between_logins_slows_down)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    for (int cycle = 0; cycle < 4; cycle++) {
        for (int g = 0; g < 3; g++) {
            mw_device_auth_forget();
            mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
            CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
        }
        CHECK_EQ_INT(login("first-password"), MW_OK);
    }
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
    CHECK(mw_device_auth_lockout_ms() >= 60000u);
    // Clean unlocks bring it down again, one per ten unlocks in a row.
    mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
    for (int i = 0; i < 90; i++) CHECK_EQ_INT(login("first-password"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
    CHECK_EQ_INT(mw_device_auth_lockout_ms(), 0u);
}

// One guess, then a login and a re-check of the own password, again and
// again: the re-checks and logins do not wash the guesses out.
MW_TEST(test_guess_login_recheck_cycle_slows_down)
{
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    for (int cycle = 0; cycle < 10; cycle++) {
        mw_device_auth_forget();
        mw_host_advance_ms(mw_device_auth_lockout_ms() + 1u);
        CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
        CHECK_EQ_INT(login("first-password"), MW_OK);
        CHECK_EQ_INT(mw_device_auth_check("first-password"), MW_OK);
    }
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
    const uint32_t d1 = mw_device_auth_lockout_ms();
    CHECK(d1 >= 30000u);                           // 11 guesses: half a minute
    CHECK_EQ_INT(mw_device_auth_verify("first-password"), MW_ERR_ABORTED);
    mw_host_advance_ms(d1 + 1u);
    CHECK_EQ_INT(login("first-password"), MW_OK);
    mw_device_auth_forget();
    CHECK_EQ_INT(mw_device_auth_verify("a-guess"), MW_ERR_DECRYPT);
    CHECK(mw_device_auth_lockout_ms() >= 2u * d1 - 1000u);  // and doubling
}

// Every account has a name of its own; only that account sees it.
MW_TEST(test_account_names)
{
    char name[MW_ACCOUNT_NAME_LEN];
    fresh();
    CHECK_EQ_INT(mw_device_auth_set("first-password"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_account_name(name, sizeof name), MW_OK);
    CHECK_EQ_STR(name, "Main");
    CHECK_EQ_INT(mw_device_auth_add_user("second-password", "Savings"), MW_OK);
    CHECK_EQ_INT(mw_device_auth_add_user("third-password", "0123456789abcdef"), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_store_account_name(name, sizeof name), MW_OK);
    CHECK_EQ_STR(name, "Main");
    CHECK_EQ_INT(mw_wallet_store_account_rename("Daily"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_account_rename(""), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_store_account_rename("   "), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_store_account_rename("0123456789abcdef"), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(login("second-password"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_account_name(name, sizeof name), MW_OK);
    CHECK_EQ_STR(name, "Savings");
    // The name follows a password change.
    CHECK_EQ_INT(mw_device_auth_change("second-password", "second-new-pw"), MW_OK);
    reboot();
    CHECK_EQ_INT(mw_device_auth_verify("first-password"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_account_name(name, sizeof name), MW_OK);
    CHECK_EQ_STR(name, "Daily");
    CHECK_EQ_INT(login("second-new-pw"), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_account_name(name, sizeof name), MW_OK);
    CHECK_EQ_STR(name, "Savings");
    CHECK_EQ_INT(mw_device_auth_add_user("1234567", NULL), MW_ERR_INVALID_ARG);  // 8 at least
}

int main(void)
{
    RUN_TEST(test_users_are_isolated);
    RUN_TEST(test_add_user_rules);
    RUN_TEST(test_user_limit);
    RUN_TEST(test_delete_other_user);
    RUN_TEST(test_delete_first_user);
    RUN_TEST(test_change_other_user_password);
    RUN_TEST(test_first_user_change_keeps_others);
    RUN_TEST(test_other_user_change_interrupted);
    RUN_TEST(test_legacy_directory_migrated);
    RUN_TEST(test_shared_attempt_counter);
    RUN_TEST(test_empty_legacy_blob_ignored);
    RUN_TEST(test_directory_bak_recovered);
    RUN_TEST(test_first_user_change_leftover);
    RUN_TEST(test_guessing_between_logins_slows_down);
    RUN_TEST(test_guess_login_recheck_cycle_slows_down);
    RUN_TEST(test_account_names);
    mw_host_store_reset();
    return mw_test_summary();
}
