// Key derivation: seed -> account keys plus the one-time key / ECDH helpers
// (TZ 6.2, 7.x, 8.3). Every formula matches monero-project/monero's
// crypto::* and rct::* functions.
#include "keys.h"

#include <string.h>

#include "../crypto/hash.h"
#include "../crypto/memzero.h"

// ------------------------------------------------------------------ helpers
static void ge_p3_to_p2(mw_ge_p2* r, const mw_ge_p3* p)
{
    memcpy(r->X, p->X, sizeof(mw_fe));
    memcpy(r->Y, p->Y, sizeof(mw_fe));
    memcpy(r->Z, p->Z, sizeof(mw_fe));
}

// Monero's write_varint for a 32-bit value; returns the number of bytes.
static size_t varint_write(uint64_t v, uint8_t out[10])
{
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

// view secret = sc_reduce32(keccak256(spend secret))
static void view_from_spend(const mw_seckey_t* spend, mw_seckey_t* view_out)
{
    uint8_t h[32];
    mw_keccak256(spend->b, 32, h);
    memcpy(view_out->b, h, 32);
    mw_sc_reduce32(view_out);
    mw_memzero(h, sizeof(h));
}

// ------------------------------------------------------------- account keys
void mw_keys_from_legacy_seed(const uint8_t seed[32], mw_account_keys_t* out)
{
    if (seed == NULL || out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->sec.spend.b, seed, 32);
    mw_sc_reduce32(&out->sec.spend);
    view_from_spend(&out->sec.spend, &out->sec.view);
    out->view_only = false;
}

void mw_keys_from_polyseed_key(const uint8_t key[32], mw_account_keys_t* out)
{
    // Polyseed's KDF output is used exactly like a legacy seed.
    mw_keys_from_legacy_seed(key, out);
}

mw_err_t mw_keys_derive_public(mw_account_keys_t* keys)
{
    if (keys == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    if (!keys->view_only) {
        mw_point_scalarmult_base(&keys->pub.spend, &keys->sec.spend);
    }
    mw_point_scalarmult_base(&keys->pub.view, &keys->sec.view);

    // TZ 8.3: re-check x*G == P before the keys are used anywhere.
    mw_err_t err = mw_check_key_pair(&keys->sec.view, &keys->pub.view);
    if (err != MW_OK) {
        return err;
    }
    if (!keys->view_only) {
        err = mw_check_key_pair(&keys->sec.spend, &keys->pub.spend);
        if (err != MW_OK) {
            return err;
        }
    }
    return MW_OK;
}

mw_err_t mw_check_key_pair(const mw_seckey_t* sec, const mw_pubkey_t* pub)
{
    if (sec == NULL || pub == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    mw_point_t check;
    mw_point_scalarmult_base(&check, sec);
    int ok = mw_point_eq(&check, pub);
    mw_memzero(&check, sizeof(check));
    return ok ? MW_OK : MW_ERR_KEY_MISMATCH;
}

// ---------------------------------------------------------- key derivation
mw_err_t mw_generate_key_derivation(const mw_pubkey_t* pub, const mw_seckey_t* sec,
                                    mw_point_t* derivation_out)
{
    if (pub == NULL || sec == NULL || derivation_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(sec)) {
        return MW_ERR_INVALID_ARG;
    }

    mw_ge_p3 point;
    if (mw_ge_frombytes_vartime(&point, pub) != 0) {
        return MW_ERR_FORMAT;
    }

    mw_ge_p3 prod;
    mw_ge_scalarmult(&prod, sec, &point);       // r*A

    mw_ge_p2 p2;
    ge_p3_to_p2(&p2, &prod);

    mw_ge_p1p1 eight;
    mw_ge_mul8(&eight, &p2);                    // 8*r*A

    mw_ge_p3 result;
    mw_ge_p1p1_to_p3(&result, &eight);
    mw_ge_p3_tobytes(derivation_out, &result);

    mw_memzero(&prod, sizeof(prod));
    mw_memzero(&p2, sizeof(p2));
    mw_memzero(&eight, sizeof(eight));
    mw_memzero(&result, sizeof(result));
    return MW_OK;
}

void mw_derivation_to_scalar(const mw_point_t* derivation, uint32_t output_index,
                             mw_scalar_t* out)
{
    if (derivation == NULL || out == NULL) {
        return;
    }
    uint8_t buf[32 + 10];
    memcpy(buf, derivation->b, 32);
    size_t n = 32 + varint_write(output_index, buf + 32);
    mw_hash_to_scalar(buf, n, out);
    mw_memzero(buf, sizeof(buf));
}

mw_err_t mw_derive_public_key(const mw_point_t* derivation, uint32_t output_index,
                              const mw_pubkey_t* base, mw_pubkey_t* out)
{
    if (derivation == NULL || base == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    mw_scalar_t scalar;
    mw_derivation_to_scalar(derivation, output_index, &scalar);

    mw_ge_p3 base_point;
    if (mw_ge_frombytes_vartime(&base_point, base) != 0) {
        mw_memzero(&scalar, sizeof(scalar));
        return MW_ERR_FORMAT;
    }

    mw_ge_p3 scalar_g;
    mw_ge_scalarmult_base(&scalar_g, &scalar);      // Hs(D||i)*G

    mw_ge_cached cached;
    mw_ge_p3_to_cached(&cached, &scalar_g);

    mw_ge_p1p1 sum;
    mw_ge_add(&sum, &base_point, &cached);          // B + Hs(D||i)*G

    mw_ge_p2 res;
    mw_ge_p1p1_to_p2(&res, &sum);
    mw_ge_p2_tobytes(out, &res);

    mw_memzero(&scalar, sizeof(scalar));
    mw_memzero(&scalar_g, sizeof(scalar_g));
    mw_memzero(&cached, sizeof(cached));
    mw_memzero(&sum, sizeof(sum));
    mw_memzero(&res, sizeof(res));
    return MW_OK;
}

void mw_derive_secret_key(const mw_point_t* derivation, uint32_t output_index,
                          const mw_seckey_t* base, mw_seckey_t* out)
{
    if (derivation == NULL || base == NULL || out == NULL) {
        return;
    }
    mw_scalar_t scalar;
    mw_derivation_to_scalar(derivation, output_index, &scalar);
    mw_sc_add(out, base, &scalar);
    mw_memzero(&scalar, sizeof(scalar));
}

// ------------------------------------------------------------- subaddresses
void mw_get_subaddress_secret_key(const mw_seckey_t* view, uint32_t major,
                                  uint32_t minor, mw_scalar_t* out)
{
    if (view == NULL || out == NULL) {
        return;
    }
    // "SubAddr" plus its terminating NUL == 8 bytes, then a, major, minor.
    uint8_t buf[8 + 32 + 4 + 4];
    memcpy(buf, "SubAddr", 8);
    memcpy(buf + 8, view->b, 32);
    buf[40] = (uint8_t)(major);
    buf[41] = (uint8_t)(major >> 8);
    buf[42] = (uint8_t)(major >> 16);
    buf[43] = (uint8_t)(major >> 24);
    buf[44] = (uint8_t)(minor);
    buf[45] = (uint8_t)(minor >> 8);
    buf[46] = (uint8_t)(minor >> 16);
    buf[47] = (uint8_t)(minor >> 24);

    mw_hash_to_scalar(buf, sizeof(buf), out);
    mw_memzero(buf, sizeof(buf));
}

mw_err_t mw_get_subaddress(const mw_account_keys_t* keys, uint32_t major,
                           uint32_t minor, mw_address_t* out)
{
    if (keys == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));
    out->major = major;
    out->minor = minor;
    // The caller decides which network the address is printed for; mainnet is
    // the default so a freshly filled struct is usable as-is.
    out->network = MW_NET_MAINNET;

    if (major == 0 && minor == 0) {
        out->type = MW_ADDR_STANDARD;
        out->spend = keys->pub.spend;
        out->view = keys->pub.view;
        return MW_OK;
    }

    mw_scalar_t m;
    mw_get_subaddress_secret_key(&keys->sec.view, major, minor, &m);

    mw_point_t mG;
    mw_point_scalarmult_base(&mG, &m);

    mw_point_t D;                                // D = B + m*G
    if (mw_point_add(&D, &keys->pub.spend, &mG) != 0) {
        mw_memzero(&m, sizeof(m));
        return MW_ERR_FORMAT;
    }

    mw_point_t C;                                // C = a*D
    if (mw_point_scalarmult(&C, &keys->sec.view, &D) != 0) {
        mw_memzero(&m, sizeof(m));
        return MW_ERR_FORMAT;
    }

    out->type = MW_ADDR_SUBADDRESS;
    out->spend = D;
    out->view = C;

    mw_memzero(&m, sizeof(m));
    return MW_OK;
}

// ---------------------------------------------------------------- RCT ECDH
void mw_ecdh_hash(const mw_scalar_t* shared, uint8_t out[32])
{
    if (shared == NULL || out == NULL) {
        return;
    }
    uint8_t buf[6 + 32];
    memcpy(buf, "amount", 6);
    memcpy(buf + 6, shared->b, 32);
    mw_keccak256(buf, sizeof(buf), out);
    mw_memzero(buf, sizeof(buf));
}

static void ecdh_commitment_mask(const mw_scalar_t* shared, mw_ecdh_mask_t* out)
{
    uint8_t buf[15 + 32];
    memcpy(buf, "commitment_mask", 15);
    memcpy(buf + 15, shared->b, 32);
    mw_hash_to_scalar(buf, sizeof(buf), out);
    mw_memzero(buf, sizeof(buf));
}

void mw_ecdh_decode(const mw_scalar_t* shared, uint64_t* amount_inout,
                    mw_ecdh_mask_t* mask_out)
{
    if (shared == NULL) {
        return;
    }
    if (mask_out != NULL) {
        ecdh_commitment_mask(shared, mask_out);
    }
    if (amount_inout != NULL) {
        uint8_t h[32];
        mw_ecdh_hash(shared, h);
        uint64_t pad = 0;
        for (int i = 7; i >= 0; --i) {
            pad = (pad << 8) | h[i];         // little-endian
        }
        *amount_inout ^= pad;
        mw_memzero(h, sizeof(h));
    }
}

void mw_ecdh_encode(const mw_scalar_t* shared, uint64_t amount,
                    uint8_t amount_out[8], mw_ecdh_mask_t* mask_out)
{
    if (shared == NULL) {
        return;
    }
    if (mask_out != NULL) {
        ecdh_commitment_mask(shared, mask_out);
    }
    if (amount_out != NULL) {
        uint8_t h[32];
        mw_ecdh_hash(shared, h);
        for (int i = 0; i < 8; ++i) {
            amount_out[i] = (uint8_t)((amount >> (8 * i)) & 0xff) ^ h[i];
        }
        mw_memzero(h, sizeof(h));
    }
}
