// Key derivation: seed -> account keys, and the one-time key / ECDH helpers
// used during signing.
#ifndef MW_KEYS_H
#define MW_KEYS_H

#include "monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Legacy: spend = sc_reduce32(seed); view = Hs(spend).
void mw_keys_from_legacy_seed(const uint8_t seed[32], mw_account_keys_t* out);

// Polyseed: the 32-byte key from polyseed_keygen() is the spend key material.
void mw_keys_from_polyseed_key(const uint8_t key[32], mw_account_keys_t* out);

// Derives the public halves and fills `pub`. Also re-checks x*G == P
// (TZ 8.3) and returns MW_ERR_KEY_MISMATCH on failure.
mw_err_t mw_keys_derive_public(mw_account_keys_t* keys);

// Key derivation D = 8 * r * A   (sender) or  8 * a * R (receiver).
mw_err_t mw_generate_key_derivation(const mw_pubkey_t* pub, const mw_seckey_t* sec,
                                    mw_point_t* derivation_out);

// scalar = Hs(derivation || varint(output_index))
void mw_derivation_to_scalar(const mw_point_t* derivation, uint32_t output_index,
                             mw_scalar_t* out);

// One-time public key: P = Hs(D||i)*G + B
mw_err_t mw_derive_public_key(const mw_point_t* derivation, uint32_t output_index,
                              const mw_pubkey_t* base, mw_pubkey_t* out);

// One-time secret key: x = Hs(D||i) + b
void mw_derive_secret_key(const mw_point_t* derivation, uint32_t output_index,
                          const mw_seckey_t* base, mw_seckey_t* out);

// Subaddress secret key m = Hs("SubAddr\0" || a || major || minor)
void mw_get_subaddress_secret_key(const mw_seckey_t* view, uint32_t major,
                                  uint32_t minor, mw_scalar_t* out);

mw_err_t mw_get_subaddress(const mw_account_keys_t* keys, uint32_t major,
                           uint32_t minor, mw_address_t* out);

// ECDH amount/mask encoding used by RCT (BulletproofPlus / "v2" short form).
void mw_ecdh_hash(const mw_scalar_t* shared, uint8_t out[32]);
void mw_ecdh_decode(const mw_scalar_t* shared, uint64_t* amount_inout,
                    mw_ecdh_mask_t* mask_out);
void mw_ecdh_encode(const mw_scalar_t* shared, uint64_t amount,
                    uint8_t amount_out[8], mw_ecdh_mask_t* mask_out);

// Verifies that `sec` is really the discrete log of `pub` (TZ 8.3).
mw_err_t mw_check_key_pair(const mw_seckey_t* sec, const mw_pubkey_t* pub);

#ifdef __cplusplus
}
#endif
#endif
