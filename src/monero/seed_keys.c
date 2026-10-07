// Seed material -> account keys, including the seed offset passphrase.
//
// The passphrase scheme is Monero's "seed offset" exactly as Monero CLI, the
// GUI and Feather apply it (cryptonote::decrypt_key(), wallet api
// WalletImpl::recover() / recoverDeterministicWalletFromSpendKey()):
//
//     key32   = the 32 bytes the seed encodes
//               legacy 25 words : the decoded seed
//               polyseed 16 words: polyseed_keygen() output (Feather hands it
//                                  to createDeterministicWalletFromSpendKey)
//     if passphrase != "":
//         key32 = sc_sub(key32, cn_slow_hash(passphrase))     <- ref10 sc_sub
//     spend   = sc_reduce32(key32)
//     view    = sc_reduce32(keccak256(spend))
//
// An empty passphrase is a genuine no-op, which is what makes "no passphrase"
// the plain Monero / Feather wallet of the same phrase.
//
// Polyseed's own passphrase feature (the "encrypted" flag, polyseed_crypt) is
// deliberately NOT used: Feather restores a polyseed with a seed offset through
// the spend-key path above, so that is the scheme a phrase written down on this
// device must reproduce there (ТЗ 2.0 §3.1).
#include "mnemonic.h"
#include "keys.h"
#include "../config/app_config.h"

#include <string.h>

#include "../crypto/chacha.h"          // mw_cn_slow_hash
#include "../crypto/ed25519.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"

static int passphrase_used(const char* passphrase)
{
    return passphrase != NULL && passphrase[0] != '\0';
}

mw_err_t mw_seed_offset_apply(uint8_t key32[32], const char* passphrase)
{
    if (key32 == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!passphrase_used(passphrase)) {
        return MW_OK;
    }
    uint8_t h[32];
    if (mw_cn_slow_hash(passphrase, strlen(passphrase), h) != 0) {
        mw_memzero(h, sizeof(h));
        return MW_ERR_MEMORY;                  // no scratchpad for CryptoNight
    }
    uint8_t out[32];
    mw_sc_sub_ref10(out, key32, h);
    memcpy(key32, out, 32);
    mw_memzero(out, sizeof(out));
    mw_memzero(h, sizeof(h));
    return MW_OK;
}

mw_err_t mw_seed_to_keys(mw_seed_type_t type, const uint8_t* seed_material,
                         size_t seed_len, const char* passphrase,
                         mw_account_keys_t* keys_out)
{
    if (seed_material == NULL || keys_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    uint8_t  key[32];
    mw_err_t err;

    if (type == MW_SEED_MONERO_LEGACY) {
        if (seed_len != 32) {
            return MW_ERR_INVALID_ARG;
        }
        memcpy(key, seed_material, 32);

    } else if (type == MW_SEED_POLYSEED) {
        mw_polyseed_t seed;
        memset(&seed, 0, sizeof(seed));

        // Only the packed context is accepted: the birthday and the feature
        // bits are part of the KDF salt, a bare secret would derive a foreign
        // wallet (see mnemonic.h).
        err = mw_polyseed_unpack(seed_material, seed_len, &seed);
        if (err != MW_OK) {
            mw_memzero(&seed, sizeof(seed));
            return err;
        }
        mw_polyseed_keygen(&seed, MW_POLYSEED_COIN_MONERO, key);
        mw_memzero(&seed, sizeof(seed));

    } else {
        return MW_ERR_NOT_SUPPORTED;
    }

    err = mw_seed_offset_apply(key, passphrase);
    if (err != MW_OK) {
        mw_memzero(key, sizeof(key));
        return err;
    }

    // spend = sc_reduce32(key), view = sc_reduce32(keccak(spend)) - the
    // account_base::generate(recover = true) path, same for both formats.
    mw_keys_from_legacy_seed(key, keys_out);
    mw_memzero(key, sizeof(key));

    err = mw_keys_derive_public(keys_out);
    if (err != MW_OK) {
        mw_memzero(keys_out, sizeof(*keys_out));
    }
    return err;
}

// ---------------------------------------------------------- dice entropy
// TZ 6.4 / 13.4. The password is the throw sequence written out as ASCII
// digits ('1'..'6'), with no separator and no terminator, exactly as the dice
// screen collects it.
mw_err_t mw_dice_to_entropy(const uint8_t* rolls, size_t n, uint8_t out[32])
{
    if (rolls == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (n < MW_DICE_ROLLS_REQUIRED) {
        return MW_ERR_INVALID_ARG;      // not enough entropy to make a seed
    }
    if (n > MW_DICE_ROLLS_MAX) {
        return MW_ERR_TOO_MANY;
    }
    for (size_t i = 0; i < n; ++i) {
        if (rolls[i] < 1u || rolls[i] > 6u) {
            return MW_ERR_RANGE;
        }
    }

    char ascii[MW_DICE_ROLLS_MAX + 1];
    for (size_t i = 0; i < n; ++i) {
        ascii[i] = (char)('0' + rolls[i]);
    }
    ascii[n] = '\0';

    static const char salt[] = "Monero dice entropy";
    mw_pbkdf2_sha512((const uint8_t*)ascii, n,
                     (const uint8_t*)salt, sizeof(salt) - 1,
                     MW_DICE_PBKDF2_ROUNDS, out, 32);

    mw_memzero(ascii, sizeof(ascii));
    return MW_OK;
}
