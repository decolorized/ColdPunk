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
// Storage: one sealed file per (wallet id, variant) in the file store,
// AES-256-GCM under the device key (mw_seal) - key images link outputs to
// the wallet, which is private information.
#ifndef MW_KI_CACHE_H
#define MW_KI_CACHE_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_KI_CACHE_MAX   4096

#define MW_KI_F_EXPORTED  0x01   // produced by a key image export
#define MW_KI_F_SPENT     0x02   // an input of a transaction this device signed
#define MW_KI_F_CHANGE    0x04   // change of a transaction this device signed

typedef struct {
    mw_pubkey_t   out_pub;       // the output's one-time public key
    mw_keyimage_t image;
    uint32_t      major, minor;  // subaddress of the output
    uint8_t       flags;
} mw_ki_entry_t;

// Loads (or starts empty) the cache of wallet `wallet_id`, passphrase
// variant `variant` (0 = no passphrase, 1 = with). `keys` binds the file to
// the account: a file whose account hash differs is ignored and replaced.
mw_err_t mw_ki_cache_open(uint32_t wallet_id, uint8_t variant,
                          const mw_account_keys_t* keys);
// Wipes the RAM copy (does not save).
void     mw_ki_cache_close(void);
bool     mw_ki_cache_is_open(void);
uint32_t mw_ki_cache_count(void);

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
// MW_ERR_TOO_MANY when the cache is full (the oldest entries are NOT evicted:
// a silently forgotten key image would make a spent output look unknown).
mw_err_t mw_ki_cache_put(const mw_ki_entry_t* e);
// Sets MW_KI_F_SPENT on the entry with this key image (no-op if absent).
void     mw_ki_cache_mark_spent(const mw_keyimage_t* image);
mw_err_t mw_ki_cache_save(void);

// Removes both variants of a wallet (wallet deletion).
mw_err_t mw_ki_cache_erase_wallet(uint32_t wallet_id);

// Device password change: re-seals both cache files of a wallet from the
// user key `old_key` to `new_key` (the seal key mixes in the password). A
// file that cannot be re-sealed is removed - the cache is rebuilt by the
// next key image export - so a password change never fails because of it.
// Leaves `new_key` installed.
void     mw_ki_cache_rekey(uint32_t wallet_id, const uint8_t old_key[32],
                           const uint8_t new_key[32]);

#ifdef __cplusplus
}
#endif
#endif
