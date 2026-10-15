// Multi-wallet storage in encrypted NVS (TZ 7, 8.1).
#ifndef MW_WALLET_STORE_H
#define MW_WALLET_STORE_H

#include "../monero/monero_types.h"
#include "../config/app_config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Passphrase hint: up to 31 bytes and the NUL.
#define MW_PP_HINT_LEN 32

// TZ 7.1 - layout kept byte-compatible with the spec.
typedef struct {
    uint32_t id;
    char     name[WALLET_NAME_LEN];
    uint8_t  encrypted_seed[64];
    uint8_t  seed_iv[16];
    uint8_t  seed_tag[16];
    uint32_t restore_height;
    uint8_t  wallet_type;        // 0 = Monero legacy, 1 = Polyseed
    bool     is_view_only;
    bool     is_hidden;
    // task 3 item 5: MW_PP_* - whether a passphrase variant exists. The check
    // value itself lives inside the sealed record, never in the directory.
    uint8_t  pp_state;
    // Optional hint for the passphrase (v9.2), shown before it is asked.
    char     pp_hint[MW_PP_HINT_LEN];
    // v0.3: the wallet's network (MW_WNET_*; MW_WNET_DEFAULT = the device
    // setting, for records written before 0.3) and a balance the user typed
    // in (piconero, valid while MW_BAL_MANUAL is set).
    uint8_t  network;
    uint8_t  bal_flags;
    uint64_t bal_manual;
} wallet_entry_t;

// wallet_entry_t.network
#define MW_WNET_DEFAULT  0
#define MW_WNET_MAINNET  1
#define MW_WNET_STAGENET 2
#define MW_WNET_TESTNET  3
// wallet_entry_t.bal_flags
#define MW_BAL_MANUAL    0x01

// wallet_entry_t.pp_state
#define MW_PP_UNKNOWN  0   // record from an older firmware: ask, cannot verify
#define MW_PP_NONE     1   // created without a passphrase: never ask
#define MW_PP_SET      2   // created with one: ask, verify, empty = base wallet

// Name of a user (account), kept in its sealed directory.
#define MW_ACCOUNT_NAME_LEN 16          // bytes with the NUL

typedef struct {
    wallet_entry_t wallets[MAX_WALLETS];
    uint32_t       count;
    uint32_t       active_wallet_id;
    char           account[MW_ACCOUNT_NAME_LEN];
    uint32_t       ki_gen;            // key image container generation (ki_cache.c)
    uint8_t        uid[16];           // v0.3: random, fixed for the account's life
    uint32_t       ki_warned;         // container size (64 KiB steps) last warned about
    uint8_t        opts;              // MW_ACC_OPT_*
    uint8_t        fmt;               // 0.3.2: storage format reached (upgrade())
} wallet_store_t;

// wallet_store_t.opts
#define MW_ACC_OPT_NO_BALANCE 0x01    // balance estimate and tx list switched off

mw_err_t mw_wallet_store_init(void);
mw_err_t mw_wallet_store_load(wallet_store_t* out);
mw_err_t mw_wallet_store_save(const wallet_store_t* store);

// Seals `seed_material` with the eFuse-backed HMAC key (AES-GCM) and appends
// a new wallet.
//
//   MW_SEED_MONERO_LEGACY : `seed_material` is the raw 32-byte seed.
//   MW_SEED_POLYSEED      : `seed_material` is the PACKED context produced by
//                           mw_polyseed_pack() - birthday || features ||
//                           secret, MW_POLYSEED_BLOB_MIN..MAX bytes.  The bare
//                           19-byte secret is refused (MW_ERR_INVALID_ARG):
//                           the birthday and the feature bits are inputs to
//                           the spend-key KDF, so dropping them derives a
//                           foreign, unrecoverable wallet.
mw_err_t mw_wallet_create(const char* name, mw_seed_type_t type,
                          const uint8_t* seed_material, size_t seed_len,
                          uint32_t restore_height, uint32_t* id_out);

// Same, recording the passphrase variant (task 3 item 5). `pp_keys` are the
// keys derived WITH the passphrase; NULL means "created without one". Only a
// 14-byte check of the passphrase wallet's public keys is kept, sealed with
// the seed - never the passphrase itself.
mw_err_t mw_wallet_create_pp(const char* name, mw_seed_type_t type,
                             const uint8_t* seed_material, size_t seed_len,
                             uint32_t restore_height,
                             const mw_account_keys_t* pp_keys, uint32_t* id_out);

// MW_PP_* of a wallet (MW_PP_NONE for raw-key imports).
uint8_t  mw_wallet_pp_state(uint32_t id);

// Opens a wallet for use:
//   passphrase ""        the base wallet (no passphrase)
//   passphrase non-empty the passphrase wallet; for MW_PP_SET the derived
//                        keys must match the sealed check, otherwise
//                        MW_ERR_DECRYPT ("wrong passphrase")
// *verified tells whether the check could be applied (false for
// MW_PP_UNKNOWN records).
mw_err_t mw_wallet_open(uint32_t id, const char* passphrase,
                        mw_account_keys_t* keys_out, bool* verified);

// Decrypts the seed into `out` (caller wipes it). Requires the device to be
// unlocked. TZ 8.1: the plaintext seed never lives longer than one operation.
// What comes back is the same payload that was sealed, i.e. the packed
// polyseed context for a polyseed wallet. `cap` must be >= 64.
mw_err_t mw_wallet_unseal_seed(uint32_t id, uint8_t* out, size_t cap, size_t* len);

// Full pipeline: unseal -> derive keys with `passphrase` -> wipe seed.
mw_err_t mw_wallet_load_keys(uint32_t id, const char* passphrase,
                             mw_account_keys_t* keys_out);

// TZ 7.2 - secure erase: the NVS record is overwritten before deletion.
mw_err_t mw_wallet_delete(uint32_t id);
// TZ 4.2: import a wallet from raw keys instead of a seed.
//
// Full wallet   : spend != NULL. `view` may be NULL, in which case it is
//                 recomputed as Hs(spend); `spend_pub` is ignored.
// View-only     : spend == NULL. Then `view` and `spend_pub` are BOTH
//                 required - a view-only wallet is defined by the private
//                 view key plus the PUBLIC spend key, and without the latter
//                 the account's address cannot even be displayed.
//
// A view-only wallet can neither sign transactions nor compute key images
// (both need the private spend key), so is_view_only is set and every such
// operation must refuse early with a clear message.
mw_err_t mw_wallet_create_from_keys(const char* name, const mw_seckey_t* spend,
                                    const mw_seckey_t* view,
                                    const mw_pubkey_t* spend_pub,
                                    uint32_t restore_height, uint32_t* id_out);

// TZ 7.1: hidden wallets are skipped by the wallet list unless it is unlocked
// with the "show hidden" toggle.
mw_err_t mw_wallet_set_hidden(uint32_t id, bool hidden);

mw_err_t mw_wallet_rename(uint32_t id, const char* name);
mw_err_t mw_wallet_set_active(uint32_t id);
const wallet_entry_t* mw_wallet_get(uint32_t id);

// Number of wallets of the user that is logged in.
mw_err_t mw_wallet_store_count(uint32_t* count);

// ---------------- users (multi-user, v9) -------------------------------------
// The device always holds exactly MW_USER_FILES_MAX slots - a directory
// "u<hex>" and a key image container "c<hex>" each: one per account, the
// rest decoys of the same size. A decoy carries a mark only this chip can
// compute (eFuse HMAC), so the firmware can give it to a new account while a
// flash dump shows the same files whatever the number of accounts. How many
// accounts fit is MW_USERS_MIN..MW_USER_FILES_MAX, fixed per chip and known
// only to it, so filling the slots does not tell how many there were.
#define MW_USER_FILES_MAX  MW_USERS_SLOTS

// Every user's directory is one sealed file in the file store, named
//   "u" + 24 hex digits of HMAC(user key, "mw.user.dir.v1")
// and sealed under that user's key: without the password a directory is
// indistinguishable from the random decoy files kept next to them, so the
// number of users cannot be read from the device.
//
// The functions below that take a `key` work on that user without disturbing
// the one that is logged in (the installed key is restored).

// Drops the in-RAM directory (lock, user switch). The next access loads the
// directory of whichever user key is installed then.
void     mw_wallet_store_close(void);

// MW_OK when `key` has a directory. *info (may be NULL) gets
//   MW_USER_SUPERSEDED  the directory belongs to an interrupted password
//                       change and the new key (copied to new_key, may be
//                       NULL) is the one to use;
//   MW_USER_PRIMARY     it is the first user's directory.
// MW_ERR_DECRYPT when there is none (or it does not open); other codes are
// storage faults (memory, I/O).
#define MW_USER_SUPERSEDED 0x01
#define MW_USER_PRIMARY    0x02
mw_err_t mw_wallet_store_user_probe(const uint8_t key[32], uint8_t* info,
                                    uint8_t new_key[32]);
// Marks the logged-in user's directory as the first user's (see probe()).
mw_err_t mw_wallet_store_mark_primary(void);
// Creates an empty directory for `key` named `name` (NULL or "": "Account")
// in place of a decoy. MW_ERR_EXISTS when `key` has one, MW_ERR_TOO_MANY
// when every slot is a user.
mw_err_t mw_wallet_store_user_create(const uint8_t key[32], const char* name);
// Removes every wallet, key image cache and the directory of the user that
// is logged in. The key stays installed; the caller forgets it.
mw_err_t mw_wallet_store_user_destroy(void);
// Directory files on the device (users + decoys); -1 on an I/O error.
int      mw_wallet_store_user_files(void);
// Brings the number of directory files back to MW_USER_FILES_MAX: adds
// decoys when there are fewer (first start, a deleted user), drops decoys
// when there are more (a cut between creating a user and dropping a decoy).
mw_err_t mw_wallet_store_decoys_ensure(void);

// Progress of the slow storage work (decoys written: first setup, the
// storage update), `done` of `total` files; NULL switches it off.
typedef void (*mw_wallet_store_progress_fn)(uint32_t done, uint32_t total, void* ctx);
void     mw_wallet_store_set_progress(mw_wallet_store_progress_fn fn, void* ctx);

// Whether a slot is free for another user (a decoy is left).
bool     mw_wallet_store_slot_free(void);

// The logged-in user's account name ("" when none) and its rename: 1..15
// bytes, no control characters.
mw_err_t mw_wallet_store_account_name(char* out, size_t cap);
mw_err_t mw_wallet_store_account_rename(const char* name);
// Whether anything of a user is stored (a directory or decoy file, or the
// old NVS directory): a password record missing next to it means damage.
bool     mw_wallet_store_any_data(void);

// One-off move of a directory kept by firmware before v9 (NVS blob
// "wallets", key image caches under the old names) to the user that is
// logged in. MW_OK when there was nothing to move.
mw_err_t mw_wallet_store_migrate_legacy(void);

// Finishes an interrupted password change of the logged-in user (its
// directory says so). MW_OK when there was nothing to finish.
mw_err_t mw_wallet_store_resume(void);

// Re-seals the logged-in user's wallets, key image caches and directory from
// old_key to new_key (password change). Crash-safe: once the directory under
// new_key is written the change is committed, and an interruption after that
// is finished at the next login with either password (resume()/probe()).
// Before that point a failure leaves everything under old_key. Leaves
// new_key installed on success, old_key on failure.
mw_err_t mw_wallet_store_rekey(const uint8_t old_key[32], const uint8_t new_key[32]);
// Whether the last rekey() reached its commit point. When it returns an
// error with this true, nothing was rolled back: the change stays pending
// and the next login finishes it (new_key is installed).
bool     mw_wallet_store_rekey_committed(void);

// Generation of the account's key image container (ki_cache.c), kept in
// the sealed directory.
uint32_t mw_wallet_store_ki_gen(void);
mw_err_t mw_wallet_store_ki_gen_set(uint32_t gen);

// The 24 hex digits that name the logged-in account's slot ("u<hex>" is its
// directory, "c<hex>" its key image container).
#define MW_SLOT_HEX 24
mw_err_t mw_wallet_store_slot_hex(char out[MW_SLOT_HEX + 1]);

// The account's identity for the password counter (device_auth.c): 16
// random bytes made at the first call and kept through password changes.
mw_err_t mw_wallet_store_account_uid(uint8_t out[16]);
// Accounts on the device (slots that are not decoys); -1 on an error.
int      mw_wallet_store_accounts(void);
// Account options (MW_ACC_OPT_*).
uint8_t  mw_wallet_store_opts(void);
mw_err_t mw_wallet_store_set_opts(uint8_t opts);
// The 64 KiB steps of the key image container the user was last warned
// about (ki growth warnings, flows.cpp).
uint32_t mw_wallet_store_ki_warned(void);
mw_err_t mw_wallet_store_set_ki_warned(uint32_t steps);

// A wallet's network: its own, or the device default for MW_WNET_DEFAULT.
// Returns an mw_network_t value.
int      mw_wallet_network(uint32_t id);
mw_err_t mw_wallet_set_network(uint32_t id, uint8_t wnet);
// A manually entered balance (`set` false clears it).
mw_err_t mw_wallet_set_manual_balance(uint32_t id, bool set, uint64_t piconero);

// Passphrase hint of a wallet ("" when none); set with "" to clear. Up to
// 31 bytes, no control characters. Only this account sees it.
mw_err_t mw_wallet_pp_hint(uint32_t id, char* out, size_t cap);
mw_err_t mw_wallet_set_pp_hint(uint32_t id, const char* hint);

// Brings the logged-in account's storage to the current format: a v9.1
// directory is rewritten as v2, the per-wallet key image files of older
// firmware go into the account's container, and the container is created
// when there is none. MW_OK when there was nothing to do.
mw_err_t mw_wallet_store_upgrade(void);

#ifdef __cplusplus
}
#endif
#endif
