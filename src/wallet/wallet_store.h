// Multi-wallet storage in encrypted NVS (TZ 7, 8.1).
#ifndef MW_WALLET_STORE_H
#define MW_WALLET_STORE_H

#include "../monero/monero_types.h"
#include "../config/app_config.h"

#ifdef __cplusplus
extern "C" {
#endif

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
} wallet_entry_t;

// wallet_entry_t.pp_state
#define MW_PP_UNKNOWN  0   // record from an older firmware: ask, cannot verify
#define MW_PP_NONE     1   // created without a passphrase: never ask
#define MW_PP_SET      2   // created with one: ask, verify, empty = base wallet

typedef struct {
    wallet_entry_t wallets[MAX_WALLETS];
    uint32_t       count;
    uint32_t       active_wallet_id;
} wallet_store_t;

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

// task2 item 1 (device password change): re-seals every record from the user
// key `old_key` to `new_key`. Installs `old_key` to unseal and leaves
// `new_key` installed on success; on failure nothing is persisted and the
// in-memory directory is reloaded from storage, so the records stay under
// `old_key`.
// Number of wallets in the directory. Needs no password (the directory
// itself is not sealed); MW_ERR_FORMAT when it cannot be interpreted.
mw_err_t mw_wallet_store_count(uint32_t* count);

// Re-seals every wallet from old_key to new_key. Idempotent: a record that
// already opens under new_key is skipped, so a change interrupted by a power
// loss can simply be run again (device_auth.c).
mw_err_t mw_wallet_store_rekey(const uint8_t old_key[32], const uint8_t new_key[32]);

#ifdef __cplusplus
}
#endif
#endif
