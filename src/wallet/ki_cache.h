// Key image cache (task 3, algorithm step 9).
//
// The device remembers, per wallet and per passphrase variant, the key images
// it has handed to the online wallet: every output of a key image export and
// the change outputs of every transaction it signed. When an unsigned
// transaction arrives, each input's key image is looked up here:
//
//   * unknown          the online wallet selected an output whose key image
//                      was never synchronised - it cannot know whether that
//                      output is spent, so the user is told to run "export
//                      outputs / import key images" first. The transaction
//                      is refused.
//   * spent by device  the output was already an input of a transaction this
//                      device signed; the user is warned (the earlier
//                      transaction may never have been broadcast).
//
// The cache also remembers each output's subaddress index, which is how the
// signer finds the key of an input received on a subaddress.
//
// Storage (v9.2): one sealed container per account ("c<24 hex>" next to its
// directory "u<24 hex>"), AES-256-GCM under the account's key (mw_seal) -
// key images link outputs to the wallet, which is private information. It is
// 64 KiB at least and grows in 64 KiB steps: the number of key images is not
// limited (only by flash and RAM). See ki_cache.c.
#ifndef MW_KI_CACHE_H
#define MW_KI_CACHE_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Size step (and minimum) of an account's container file.
#define MW_KI_STORE_STEP  (64u * 1024u)
// Free space a growing container leaves on the storage partition, so that
// every account's directory and container can still be rewritten.
#define MW_KI_STORE_RESERVE (192u * 1024u)

#define MW_KI_F_EXPORTED  0x01   // produced by a key image export
#define MW_KI_F_SPENT     0x02   // an input of a transaction this device signed
#define MW_KI_F_CHANGE    0x04   // change of a transaction this device signed

// v0.3, the balance estimate (off with MW_ACC_OPT_NO_BALANCE):
#define MW_KI_B_AMOUNT    0x01   // `amount` is known
#define MW_KI_B_SPENT     0x02   // spent: by the last outputs export, or by a
                                 // transaction this device signed since

typedef struct {
    mw_pubkey_t   out_pub;       // the output's one-time public key
    mw_keyimage_t image;
    uint32_t      major, minor;  // subaddress of the output
    uint8_t       flags;
    // v0.3. Merged by put(): an entry with MW_KI_B_AMOUNT replaces amount and
    // bal (an outputs export, the change of a signed transaction); one
    // without only adds MW_KI_B_SPENT (an input of a signed transaction).
    uint64_t      amount;        // piconero
    uint8_t       bal;           // MW_KI_B_*
} mw_ki_entry_t;

// A transaction this device signed (v0.3), for the list next to the balance.
// The device has no clock: `seq` numbers them per wallet.
#define MW_KI_TX_MAX      200    // per wallet and variant; the oldest go first
#define MW_KI_TX_ADDR     16     // the start of the first recipient's address
typedef struct {
    uint32_t seq;
    uint64_t sent;               // to recipients that are not this wallet
    uint64_t fee;
    uint64_t change;
    uint8_t  n_recipients;
    uint8_t  own_only;           // every recipient was this wallet
    char     addr[MW_KI_TX_ADDR + 1];
} mw_ki_tx_t;

// Loads (or starts empty) the cache of wallet `wallet_id`, passphrase
// variant `variant` (0 = no passphrase, 1 = with). `keys` binds the file to
// the account: a file whose account hash differs is ignored and replaced.
mw_err_t mw_ki_cache_open(uint32_t wallet_id, uint8_t variant,
                          const mw_account_keys_t* keys);
// Wipes the RAM copy (does not save).
void     mw_ki_cache_close(void);
bool     mw_ki_cache_is_open(void);
uint32_t mw_ki_cache_count(void);
// True when the file found on open was an older copy than the one last
// saved (rollback); the cache was started empty instead.
bool     mw_ki_cache_rolled_back(void);

const mw_ki_entry_t* mw_ki_cache_find_pub(const mw_pubkey_t* out_pub);
const mw_ki_entry_t* mw_ki_cache_find_image(const mw_keyimage_t* image);

// Own subaddress indices the cache knows, for the destination check
// (mw_tx_check_destinations): up to `cap` distinct (major, minor) other than
// (0,0) - indices that the check's own search window would not reach first
// (accounts other than `acct` and 0, non-zero minors) - plus the highest
// account and the highest minor of account `acct` and of account 0. Returns
// the number written; all zero when the cache is closed.
uint32_t mw_ki_cache_known_indices(uint32_t acct, uint32_t* majors, uint32_t* minors,
                                   uint32_t cap, uint32_t* max_major,
                                   uint32_t* max_minor_acct, uint32_t* max_minor_main);

// Inserts or updates by out_pub; flags are OR-ed into an existing entry.
// No limit on the count; MW_ERR_MEMORY only when RAM runs out (saving may
// still fail with MW_ERR_TOO_MANY when the storage partition is full) (nothing is
// evicted: a silently forgotten key image would make a spent output look
// unknown).
mw_err_t mw_ki_cache_put(const mw_ki_entry_t* e);
// Sets MW_KI_F_SPENT on the entry with this key image (no-op if absent).
void     mw_ki_cache_mark_spent(const mw_keyimage_t* image);
mw_err_t mw_ki_cache_save(void);
// Whether the open cache has changes save() would write.
bool     mw_ki_cache_dirty(void);

// The balance estimate of the open cache: the sum of the outputs with a
// known amount that are not spent. *outputs: how many those are; *unknown:
// outputs whose amount is not known (synchronised before 0.3, or with the
// estimate off). MW_ERR_NOT_SUPPORTED when the cache is closed.
mw_err_t mw_ki_cache_balance(uint64_t* total, uint32_t* outputs, uint32_t* unknown);
// The signed transactions of the open cache, newest last.
uint32_t mw_ki_cache_tx_count(void);
bool     mw_ki_cache_tx_get(uint32_t i, mw_ki_tx_t* out);
// Records one (no-op with the estimate off or the cache closed).
mw_err_t mw_ki_cache_tx_add(const mw_ki_tx_t* t);
// The estimate switched off: every amount and every transaction list of the
// account is dropped from the container (and from the open cache).
mw_err_t mw_ki_cache_balance_forget_all(void);

// Removes both variants of a wallet (wallet deletion).
mw_err_t mw_ki_cache_erase_wallet(uint32_t wallet_id);

// ---- the account's container ------------------------------------------------
// Its name under the installed key ("" without a key); `cap` >= 26.
void     mw_ki_store_file_name(char* out, size_t cap);
// Creates an empty container when the account has none (new account);
// _gen with the generation to write (no access to the loaded directory).
mw_err_t mw_ki_store_create(void);
mw_err_t mw_ki_store_create_gen(uint32_t gen);
// Removes the container (account deletion).
mw_err_t mw_ki_store_remove(void);
// Password change: moves the container from `old_key` (name and seal) to
// `new_key`. Idempotent. One that cannot be moved is dropped - the caches
// are rebuilt by the next key image export - so a password change never
// fails because of it; MW_ERR_MEMORY / MW_ERR_IO: nothing was dropped, try
// again (the change stays pending). Leaves `new_key` installed.
mw_err_t mw_ki_store_move(const uint8_t old_key[32], const uint8_t new_key[32]);
// Size of the container file (0: none).
size_t   mw_ki_store_size(void);

// Imports the per-wallet cache files of older firmware for `wallet_id` into
// the container and removes them (and their NVS generations).
void     mw_ki_cache_import_old(uint32_t wallet_id);
// Whether such files of `wallet_id` are still there (an import failed).
bool     mw_ki_cache_old_left(uint32_t wallet_id);
// Removes those files under the installed key without importing them.
void     mw_ki_cache_drop_old(uint32_t wallet_id);

#ifdef __cplusplus
}
#endif
#endif
