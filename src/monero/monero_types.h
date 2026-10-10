// Core Monero value types shared by every module.
#ifndef MW_MONERO_TYPES_H
#define MW_MONERO_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../crypto/ed25519.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef mw_scalar_t mw_seckey_t;   // always reduced mod l
typedef mw_point_t  mw_pubkey_t;
typedef mw_point_t  mw_keyimage_t;
typedef mw_scalar_t mw_ecdh_mask_t;

typedef struct {
    mw_seckey_t spend;   // m
    mw_seckey_t view;    // n = Hs(m)
} mw_keypair_sec_t;

typedef struct {
    mw_pubkey_t spend;   // M = m*G
    mw_pubkey_t view;    // N = n*G
} mw_keypair_pub_t;

typedef struct {
    mw_keypair_sec_t sec;
    mw_keypair_pub_t pub;
    bool view_only;      // spend secret is not available
} mw_account_keys_t;

typedef enum {
    MW_NET_MAINNET  = 0,
    MW_NET_TESTNET  = 1,
    MW_NET_STAGENET = 2
} mw_network_t;

typedef enum {
    MW_ADDR_STANDARD    = 0,
    MW_ADDR_INTEGRATED  = 1,
    MW_ADDR_SUBADDRESS  = 2
} mw_address_type_t;

typedef struct {
    mw_pubkey_t       spend;
    mw_pubkey_t       view;
    mw_address_type_t type;
    mw_network_t      network;
    uint8_t           payment_id[8];   // integrated addresses only
    bool              has_payment_id;
    uint32_t          major;           // subaddress account index
    uint32_t          minor;           // subaddress index
} mw_address_t;

// Longest Monero address (integrated, base58) is 106 chars.
#define MW_ADDRESS_STR_MAX 128

typedef enum {
    MW_SEED_MONERO_LEGACY = 0,   // 25 words
    MW_SEED_POLYSEED      = 1    // 16 words
} mw_seed_type_t;

#define MW_LEGACY_SEED_WORDS 25
#define MW_POLYSEED_WORDS    16
#define MW_MAX_SEED_WORDS    25

// Monero error codes, shared across the project.
typedef enum {
    MW_OK = 0,
    MW_ERR_INVALID_ARG     = -1,
    MW_ERR_CHECKSUM        = -2,
    MW_ERR_NUM_WORDS       = -3,
    MW_ERR_UNKNOWN_WORD    = -4,
    MW_ERR_FORMAT          = -5,
    MW_ERR_MAGIC           = -6,
    MW_ERR_VERSION         = -7,
    MW_ERR_SIGNATURE       = -8,
    MW_ERR_DECRYPT         = -9,
    MW_ERR_MEMORY          = -10,
    MW_ERR_NOT_SUPPORTED   = -11,
    MW_ERR_SUBGROUP        = -12,   // point failed the l*P == 0 check
    MW_ERR_BALANCE         = -13,   // inputs != outputs + fee
    MW_ERR_KEY_MISMATCH    = -14,   // x*G != P
    MW_ERR_TOO_MANY        = -15,
    MW_ERR_IO              = -16,
    MW_ERR_ABORTED         = -17,   // user cancelled
    MW_ERR_RANGE           = -18,
    // Keyboard outcomes (TZ 5.6, 5.7). These are not failures: they are the
    // two navigation results mw_kb_run() can return besides MW_OK and
    // MW_ERR_ABORTED. They get their own codes rather than reusing
    // MW_ERR_RANGE / MW_ERR_FORMAT, because a genuine format error bubbling
    // up from the wordlist would otherwise be read as "user asked to restart"
    // and would silently wipe the phrase the user had already typed.
    MW_KB_BACK             = -19,   // step back to the previous word
    MW_KB_RESTART          = -20,   // very-long Back: clear the whole phrase
    MW_ERR_EXISTS          = -21    // already there (e.g. a password in use)
} mw_err_t;

const char* mw_err_str(mw_err_t err);

// Monero atomic units: 1 XMR = 1e12 piconero.
#define MW_ATOMIC_UNITS 1000000000000ULL
// Formats `amount` as "12.345678901234" into `out` (needs >= 32 bytes).
void mw_format_amount(uint64_t amount, char* out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif
