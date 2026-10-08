// Seed phrase encode/decode for both supported formats (TZ 5.1, 6.2, 6.3).
#ifndef MW_MNEMONIC_H
#define MW_MNEMONIC_H

#include "monero_types.h"
#include "../data/wordlist.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- Monero legacy, 25 words ---------------------------------
// 24 words carry 32 bytes (3 words per 4 bytes); word 25 is the CRC32 checksum
// word over the concatenated 3-char prefixes.
mw_err_t mw_legacy_seed_encode(const uint8_t seed[32], const mw_wordlist_t* wl,
                               uint16_t indices_out[MW_LEGACY_SEED_WORDS]);
mw_err_t mw_legacy_seed_decode(const uint16_t indices[MW_LEGACY_SEED_WORDS],
                               const mw_wordlist_t* wl, uint8_t seed_out[32]);
// Returns the index (0..23) of the word the checksum word must equal.
int mw_legacy_checksum_index(const uint16_t indices[24], const mw_wordlist_t* wl);

// ---------------- Polyseed, 16 words --------------------------------------
#define MW_POLYSEED_SECRET_BITS  150
#define MW_POLYSEED_SECRET_SIZE  19
#define MW_POLYSEED_FEATURE_BITS 5
#define MW_POLYSEED_DATE_BITS    10
#define MW_POLYSEED_EPOCH        1635768000ULL  // 2021-11-01 12:00 UTC
#define MW_POLYSEED_TIME_STEP    2629746ULL     // 1/12 Gregorian year
#define MW_POLYSEED_COIN_MONERO  0

typedef struct {
    unsigned birthday;              // 10 bits
    unsigned features;              // 5 bits
    uint8_t  secret[32];            // 150 bits used, rest zero-padded
    uint16_t checksum;              // GF(2048) element
} mw_polyseed_t;

// Creates a fresh polyseed from `entropy` (>= 19 bytes of real entropy).
// `unix_time` sets the birthday; pass 0 for "unknown" (birthday 0).
mw_err_t mw_polyseed_create(const uint8_t* entropy, size_t entropy_len,
                            uint64_t unix_time, unsigned features,
                            mw_polyseed_t* out);

// ---------------- serialized polyseed context ------------------------------
// The spend key is PBKDF2(secret, "POLYSEED key" || coin || BIRTHDAY ||
// FEATURES), so the secret alone is NOT a seed: storing or passing around the
// bare 19 bytes silently derives the wallet a phrase with birthday 0 would
// produce, which for a real phrase is a foreign address nobody can recover.
//
// This is the one byte form the whole firmware uses whenever a polyseed has to
// leave the mw_polyseed_t struct (sealed storage, mw_seed_to_keys):
//
//     [0..1]  birthday, 16-bit little-endian
//     [2]     feature bits
//     [3..]   the secret, (len - 3) bytes
//
// The checksum is deliberately absent: it is a property of the *phrase* and is
// recomputed from these three fields whenever one is needed.
#define MW_POLYSEED_BLOB_HDR  3
#define MW_POLYSEED_BLOB_MIN  (MW_POLYSEED_BLOB_HDR + MW_POLYSEED_SECRET_SIZE)  // 22
#define MW_POLYSEED_BLOB_MAX  (MW_POLYSEED_BLOB_HDR + 32)                       // 35

// Always writes MW_POLYSEED_BLOB_MIN bytes (the secret is 150 bits).
mw_err_t mw_polyseed_pack(const mw_polyseed_t* seed, uint8_t* out, size_t cap,
                          size_t* len_out);
// MW_ERR_INVALID_ARG on a bad length, MW_ERR_FORMAT when birthday or features
// do not fit their bit fields.
mw_err_t mw_polyseed_unpack(const uint8_t* blob, size_t len, mw_polyseed_t* out);

mw_err_t mw_polyseed_encode(const mw_polyseed_t* seed, const mw_wordlist_t* wl,
                            uint16_t indices_out[MW_POLYSEED_WORDS]);
mw_err_t mw_polyseed_decode(const uint16_t indices[MW_POLYSEED_WORDS],
                            const mw_wordlist_t* wl, mw_polyseed_t* out);

// PBKDF2-HMAC-SHA256, 10000 iterations, salt "POLYSEED key" + coin/birthday/
// features. Produces the 32-byte key that becomes the spend key.
void mw_polyseed_keygen(const mw_polyseed_t* seed, uint32_t coin,
                        uint8_t key_out[32]);

// Polyseed's own passphrase-encryption (feature bit 16). This is SEPARATE from
// the TZ 5.2 session passphrase; exposed so an encrypted phrase can be
// imported/exported.
void mw_polyseed_crypt(mw_polyseed_t* seed, const char* password);
int  mw_polyseed_is_encrypted(const mw_polyseed_t* seed);

uint64_t mw_polyseed_birthday_time(const mw_polyseed_t* seed);
// Approximate restore height from the birthday timestamp (TZ 6.3).
uint32_t mw_polyseed_restore_height(const mw_polyseed_t* seed, mw_network_t net);

// ---------------- passphrase (TZ 5.2, ТЗ 2.0 §3.1) -------------------------
// Both formats use Monero's "seed offset" exactly as Monero CLI / GUI and
// Feather do (cryptonote::decrypt_key):
//
//   key32 = legacy: the decoded 32-byte seed; polyseed: polyseed_keygen()
//   passphrase != ""  ->  key32 = sc_sub_ref10(key32, cn_slow_hash(passphrase))
//   spend = sc_reduce32(key32), view = sc_reduce32(keccak256(spend))
//
// The empty case is a genuine no-op, which is what makes an empty passphrase
// reproduce the plain wallet of the same phrase. See seed_keys.c.
//
// Exception - Cake Wallet / Cupcake polyseeds: a phrase with the "encrypted"
// feature flag is unmasked with the passphrase (mw_polyseed_crypt) before
// keygen and gets no seed offset; without a passphrase mw_seed_to_keys()
// returns MW_ERR_DECRYPT. The format is detected from the phrase itself.
//
// Applies the seed offset in place (no-op for NULL / ""). Needs the
// cn_slow_hash scratchpad; MW_ERR_MEMORY when it cannot be allocated.
mw_err_t mw_seed_offset_apply(uint8_t key32[32], const char* passphrase);
//
// `seed_material` is 32 raw bytes for MW_SEED_MONERO_LEGACY and the packed
// context from mw_polyseed_pack() (MW_POLYSEED_BLOB_MIN..MAX bytes) for
// MW_SEED_POLYSEED. A bare polyseed secret is REFUSED rather than defaulted to
// birthday 0 - see the comment on MW_POLYSEED_BLOB_HDR above.
mw_err_t mw_seed_to_keys(mw_seed_type_t type, const uint8_t* seed_material,
                         size_t seed_len, const char* passphrase,
                         mw_account_keys_t* keys_out);

// ---------------- dice entropy (TZ 6.4, 13.4) ------------------------------
// Turns d6 throws into 32 bytes of seed entropy:
//   PBKDF2-HMAC-SHA512(password = the throws as ASCII digits,
//                      salt     = "Monero dice entropy",
//                      rounds   = MW_DICE_PBKDF2_ROUNDS)
//
// `n` must be between MW_DICE_ROLLS_REQUIRED and MW_DICE_ROLLS_MAX and every
// roll must be 1..6; anything else is refused instead of being truncated or
// folded, so a short or corrupted throw sequence can never quietly produce a
// low-entropy wallet.
// MW_DICE_ROLLS_MAX must stay >= the UI's MW_DICE_MAX_ROLLS (screen_common.h).
#define MW_DICE_ROLLS_MAX 160

mw_err_t mw_dice_to_entropy(const uint8_t* rolls, size_t n, uint8_t out[32]);

#ifdef __cplusplus
}
#endif
#endif
