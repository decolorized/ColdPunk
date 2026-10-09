// End-to-end transaction signing (TZ 12.2).
//
// The pipeline mirrors cryptonote::construct_tx_with_tx_key() +
// rct::genRctSimple() from monero-project/monero 0.18.x:
//
//   1. VERIFY_INPUTS  re-derive every one-time secret x from the view key and
//                     the real output's tx public key (or its additional
//                     key), matching the subaddress among the wallet2 hints;
//                     check x*G == P, check mask*G + amount*H == C, then
//                     compute the key image. Inputs are sorted by key image,
//                     descending, exactly like construct_tx does.
//   2. OUTPUT_KEYS    verify the change address against our own keys (a
//                     substituted change address is refused), shuffle the
//                     outputs, pick the tx secret key r (hedged), derive every
//                     output one-time key, view tag, ECDH-masked amount and
//                     the *deterministic* output mask
//                     Hs("commitment_mask" || Hs(D||i)); encrypt the payment
//                     id (or add the dummy one construct_tx adds) and build
//                     the extra in sort_tx_extra() order.
//   3. BULLETPROOF    one aggregate BP+ proof over all outputs, checked
//                     against the output commitments (TZ 8.3).
//   4. CLSAG          pseudo-out commitments (masks summing to the output
//                     masks), the RCT message hash, then one CLSAG per input,
//                     each of which self-verifies.
//   5. SERIALIZE      the caller turns mw_signed_data_t into the RCT blob with
//                     mw_serialize_rct().
//
// Every secret buffer is wiped on the way out, including on error paths.
#include "sign.h"

#include <string.h>

#include "keys.h"
#include "key_image.h"
#include "serialize.h"
#include "file_formats.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

#define ENCRYPTED_PAYMENT_ID_TAIL 0x8d
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID 0x01

static void report(mw_sign_progress_cb cb, void* user, mw_sign_stage_t stage,
                   int permille)
{
    if (cb != NULL) {
        cb(stage, permille, user);
    }
}

// Bulletproofs+ reports its own progress (0..1000) through a global hook;
// it is forwarded as the BULLETPROOF stage while mw_bpp_prove() runs.
typedef struct { mw_sign_progress_cb cb; void* user; } bpp_bridge_t;

static void bpp_bridge(int permille, void* u)
{
    const bpp_bridge_t* b = (const bpp_bridge_t*)u;
    report(b->cb, b->user, MW_SIGN_STAGE_BULLETPROOF, permille);
}

// payment_id ^= keccak(8*r*A || 0x8d)[0..7]
static mw_err_t encrypt_payment_id(uint8_t pid[8], const mw_pubkey_t* view_pub,
                                   const mw_seckey_t* tx_sec)
{
    mw_point_t derivation;
    mw_err_t err = mw_generate_key_derivation(view_pub, tx_sec, &derivation);
    if (err != MW_OK) {
        return err;
    }
    uint8_t buf[33];
    memcpy(buf, derivation.b, 32);
    buf[32] = ENCRYPTED_PAYMENT_ID_TAIL;
    uint8_t hash[32];
    mw_keccak256(buf, sizeof(buf), hash);
    for (int i = 0; i < 8; ++i) {
        pid[i] ^= hash[i];
    }
    mw_memzero(buf, sizeof(buf));
    mw_memzero(hash, sizeof(hash));
    mw_memzero(&derivation, sizeof(derivation));
    return MW_OK;
}

// ------------------------------------------------------------- view tags
// crypto::derive_view_tag: keccak("view_tag" || derivation || varint(index))[0]
static uint8_t derive_view_tag(const mw_point_t* derivation, uint32_t index)
{
    uint8_t buf[8 + 32 + 10];
    memcpy(buf, "view_tag", 8);
    memcpy(buf + 8, derivation->b, 32);
    size_t n = 40 + mw_varint_encode(index, buf + 40);
    uint8_t hash[32];
    mw_keccak256(buf, n, hash);
    uint8_t tag = hash[0];
    mw_memzero(buf, sizeof(buf));
    mw_memzero(hash, sizeof(hash));
    return tag;
}

// --------------------------------------------------------------- helpers
static bool same_address(const mw_address_t* a, const mw_address_t* b)
{
    return mw_point_eq(&a->spend, &b->spend) && mw_point_eq(&a->view, &b->view);
}

static void amount_to_scalar(uint64_t v, mw_scalar_t* s)
{
    mw_sc_0(s);
    for (int k = 0; k < 8; ++k) {
        s->b[k] = (uint8_t)((v >> (8 * k)) & 0xff);
    }
}

// Uniform index in [0, n) by rejection sampling.
static uint32_t random_below(uint32_t n)
{
    if (n <= 1) {
        return 0;
    }
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    for (;;) {
        uint32_t v = 0;
        mw_random_bytes(&v, sizeof(v));
        if (v < limit) {
            return v % n;
        }
    }
}

// generate_key_image_helper() with the cold wallet's subaddress table replaced
// by the candidates the unsigned set itself names: the main address, the
// account's subaddresses listed in subaddr_indices (wallet2 selects inputs
// from those), (account, 0) and whatever the caller pre-set. For each of the
// two possible derivations (main tx key, additional key) the spend key
//     D' = P - Hs(8*a*R || i)*G
// is compared with the candidates' spend keys, so a candidate costs one base
// multiplication instead of a full derivation.
static mw_err_t find_input_secret(const mw_account_keys_t* keys,
                                  const mw_transaction_t* tx, mw_tx_source_t* s,
                                  mw_seckey_t* x_out)
{
    const mw_pubkey_t* P = &s->ring[s->real_output_index].dest;
    const mw_pubkey_t* tx_keys[2];
    int n_keys = 0;
    tx_keys[n_keys++] = &s->real_out_tx_key;
    if (s->has_additional_key) {
        if (!mw_point_check_public(&s->real_out_additional_key)) {
            return MW_ERR_SUBGROUP;
        }
        tx_keys[n_keys++] = &s->real_out_additional_key;
    }

    // Candidate (major, minor) list; (0,0) is compared directly below.
    uint32_t cand_major[MW_MAX_SUBADDR_HINTS + 2];
    uint32_t cand_minor[MW_MAX_SUBADDR_HINTS + 2];
    int n_cand = 0;
    if (s->subaddr_known && (s->subaddr_major != 0 || s->subaddr_minor != 0)) {
        cand_major[n_cand] = s->subaddr_major;
        cand_minor[n_cand++] = s->subaddr_minor;
    }
    for (uint8_t h = 0; h < tx->n_subaddr_hints && h < MW_MAX_SUBADDR_HINTS; ++h) {
        if (tx->subaddr_account == 0 && tx->subaddr_hints[h] == 0) {
            continue;
        }
        cand_major[n_cand] = tx->subaddr_account;
        cand_minor[n_cand++] = tx->subaddr_hints[h];
    }
    if (tx->subaddr_account != 0) {
        cand_major[n_cand] = tx->subaddr_account;
        cand_minor[n_cand++] = 0;
    }

    mw_err_t result = MW_ERR_KEY_MISMATCH;
    for (int k = 0; k < n_keys && result != MW_OK; ++k) {
        mw_point_t derivation;
        mw_err_t e = mw_generate_key_derivation(tx_keys[k], &keys->sec.view, &derivation);
        if (e != MW_OK) {
            return e;
        }
        mw_scalar_t h;
        mw_derivation_to_scalar(&derivation, s->real_output_in_tx_index, &h);
        mw_memzero(&derivation, sizeof(derivation));

        mw_point_t hG, spend_guess;
        mw_point_scalarmult_base(&hG, &h);
        if (mw_point_sub(&spend_guess, P, &hG) != 0) {
            mw_memzero(&h, sizeof(h));
            continue;
        }

        if (mw_point_eq(&spend_guess, &keys->pub.spend)) {
            mw_sc_add(x_out, &h, &keys->sec.spend);
            s->subaddr_major = 0;
            s->subaddr_minor = 0;
            result = MW_OK;
        }
        for (int c = 0; c < n_cand && result != MW_OK; ++c) {
            mw_scalar_t m;
            mw_get_subaddress_secret_key(&keys->sec.view, cand_major[c],
                                         cand_minor[c], &m);
            mw_point_t mG, sub_spend;
            mw_point_scalarmult_base(&mG, &m);
            if (mw_point_add(&sub_spend, &keys->pub.spend, &mG) == 0 &&
                mw_point_eq(&spend_guess, &sub_spend)) {
                mw_sc_add(x_out, &h, &keys->sec.spend);
                mw_sc_add(x_out, x_out, &m);
                s->subaddr_major = cand_major[c];
                s->subaddr_minor = cand_minor[c];
                result = MW_OK;
            }
            mw_memzero(&m, sizeof(m));
        }
        mw_memzero(&h, sizeof(h));
    }
    if (result != MW_OK) {
        mw_memzero(x_out, sizeof(*x_out));
        return result;
    }
    // TZ 8.3: never sign with a secret that does not open the public key.
    result = mw_check_key_pair(x_out, P);
    if (result != MW_OK) {
        mw_memzero(x_out, sizeof(*x_out));
    }
    s->subaddr_known = (result == MW_OK);
    return result;
}

// get_destination_view_key_pub(): the single non-change recipient's view
// key, the change address's when every output is change, and "none" (NULL)
// when there are several distinct recipients.
static const mw_pubkey_t* destination_view_key(const mw_transaction_t* tx)
{
    const mw_address_t* first = NULL;
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        const mw_tx_destination_t* d = &tx->destinations[i];
        if (d->amount == 0) {
            continue;
        }
        if (tx->has_change_addr && same_address(&d->addr, &tx->change_addr)) {
            continue;
        }
        if (first != NULL && same_address(&d->addr, first)) {
            continue;
        }
        if (first != NULL) {
            return NULL;
        }
        first = &d->addr;
    }
    if (first == NULL) {
        return tx->has_change_addr ? &tx->change_addr.view : NULL;
    }
    return &first->view;
}

// What the online wallet put into extra: nothing, an 8-byte payment id to
// encrypt (integrated address), or a legacy 32-byte one. The tx public key
// fields it may carry are dropped; construct_tx() replaces them.
enum { PID_NONE = 0, PID_SHORT, PID_LONG };

static mw_err_t scan_extra_in(const mw_transaction_t* tx, int* kind,
                              uint8_t pid[8], uint8_t long_pid[32])
{
    mw_reader_t r;
    mw_reader_init(&r, tx->extra_in, tx->extra_in_len);
    *kind = PID_NONE;
    int nonces = 0;
    while (mw_remaining(&r) > 0) {
        uint8_t tag = 0;
        mw_read_u8(&r, &tag);
        if (tag == 0x01) {                               // tx public key
            if (!mw_skip(&r, 32)) return MW_ERR_FORMAT;
        } else if (tag == 0x04) {                        // additional keys
            uint64_t n = 0;
            if (!mw_read_varint(&r, &n) || n > MW_MAX_OUTPUTS ||
                !mw_skip(&r, (size_t)n * 32u)) {
                return MW_ERR_FORMAT;
            }
        } else if (tag == 0x02) {                        // nonce
            uint64_t n = 0;
            if (!mw_read_varint(&r, &n) || n > 255 || n > mw_remaining(&r)) {
                return MW_ERR_FORMAT;
            }
            const uint8_t* p = r.data + r.pos;
            mw_skip(&r, (size_t)n);
            if (++nonces > 1) {
                return MW_ERR_NOT_SUPPORTED;
            }
            if (n == 9 && p[0] == 0x01) {
                *kind = PID_SHORT;
                memcpy(pid, p + 1, 8);
            } else if (n == 33 && p[0] == 0x00) {
                *kind = PID_LONG;
                memcpy(long_pid, p + 1, 32);
            } else {
                return MW_ERR_NOT_SUPPORTED;             // unknown nonce content
            }
        } else {
            return MW_ERR_NOT_SUPPORTED;                 // field construct_tx cannot sort
        }
    }
    return r.overflow ? MW_ERR_FORMAT : MW_OK;
}

mw_err_t mw_sign_input_key_image(const mw_account_keys_t* keys, mw_transaction_t* tx,
                                 uint8_t index, mw_keyimage_t* ki_out)
{
    if (keys == NULL || tx == NULL || ki_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (keys->view_only) {
        return MW_ERR_NOT_SUPPORTED;
    }
    if (index >= tx->n_inputs || index >= MW_MAX_INPUTS) {
        return MW_ERR_RANGE;
    }
    mw_tx_source_t* s = &tx->sources[index];
    if (s->ring_size == 0 || s->ring_size > MW_MAX_RING_SIZE ||
        s->real_output_index >= s->ring_size) {
        return MW_ERR_INVALID_ARG;
    }
    const mw_ctkey_t* real = &s->ring[s->real_output_index];
    if (!mw_point_check_public(&real->dest) || !mw_point_check_public(&real->mask) ||
        !mw_point_check_public(&s->real_out_tx_key)) {
        return MW_ERR_SUBGROUP;
    }
    mw_seckey_t x;
    mw_err_t err = find_input_secret(keys, tx, s, &x);
    if (err == MW_OK) {
        err = mw_generate_key_image(&real->dest, &x, ki_out);
    }
    mw_memzero(&x, sizeof(x));
    return err;
}

static void sort_inputs_by_key_image(mw_transaction_t* tx, mw_seckey_t* secrets)
{
    // Descending memcmp order over the key image, as construct_tx does.
    for (uint8_t i = 1; i < tx->n_inputs; ++i) {
        for (uint8_t j = i; j > 0; --j) {
            if (memcmp(tx->sources[j - 1].key_image.b, tx->sources[j].key_image.b,
                       32) >= 0) {
                break;
            }
            mw_tx_source_t tmp_src = tx->sources[j - 1];
            tx->sources[j - 1] = tx->sources[j];
            tx->sources[j] = tmp_src;
            mw_seckey_t tmp_sec = secrets[j - 1];
            secrets[j - 1] = secrets[j];
            secrets[j] = tmp_sec;
            mw_memzero(&tmp_src, sizeof(tmp_src));
            mw_memzero(&tmp_sec, sizeof(tmp_sec));
        }
    }
}

// --------------------------------------------------------------- signing
mw_err_t mw_sign_transaction(const mw_account_keys_t* keys, mw_transaction_t* tx,
                             mw_signed_data_t* out,
                             mw_sign_progress_cb cb, void* user)
{
    if (keys == NULL || tx == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (keys->view_only) {
        return MW_ERR_NOT_SUPPORTED;
    }

    report(cb, user, MW_SIGN_STAGE_PARSE, 0);

    if (tx->n_inputs == 0 || tx->n_inputs > MW_MAX_INPUTS ||
        tx->n_destinations == 0 || tx->n_destinations > MW_MAX_DESTINATIONS ||
        tx->n_destinations > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (tx->rct_type != 6) {
        return MW_ERR_NOT_SUPPORTED;             // only BulletproofPlus
    }

    // The fee is not an input of its own: it is whatever the inputs leave
    // after the destinations. A declared fee that disagrees is an altered
    // file (TZ 8.3).
    {
        uint64_t in_sum = 0, out_sum = 0;
        for (uint8_t i = 0; i < tx->n_inputs; ++i) {
            if (tx->sources[i].amount > UINT64_MAX - in_sum) return MW_ERR_RANGE;
            in_sum += tx->sources[i].amount;
        }
        for (uint8_t i = 0; i < tx->n_destinations; ++i) {
            if (tx->destinations[i].amount > UINT64_MAX - out_sum) return MW_ERR_RANGE;
            out_sum += tx->destinations[i].amount;
        }
        if (out_sum > in_sum || in_sum - out_sum != tx->fee) {
            return MW_ERR_BALANCE;
        }
    }

    memset(out, 0, sizeof(*out));
    tx->n_outputs = tx->n_destinations;
    memset(tx->out_ki_valid, 0, sizeof(tx->out_ki_valid));

    mw_err_t err = MW_OK;
    mw_seckey_t in_sec[MW_MAX_INPUTS];
    mw_scalar_t in_mask[MW_MAX_INPUTS];
    mw_scalar_t out_mask[MW_MAX_OUTPUTS];
    mw_scalar_t pseudo_mask[MW_MAX_INPUTS];
    mw_seckey_t add_sec[MW_MAX_OUTPUTS];
    mw_pubkey_t add_pub[MW_MAX_OUTPUTS];
    uint64_t out_amount[MW_MAX_OUTPUTS];
    uint8_t  nonce[1 + 32];
    size_t   nonce_len = 0;
    memset(in_sec, 0, sizeof(in_sec));
    memset(in_mask, 0, sizeof(in_mask));
    memset(out_mask, 0, sizeof(out_mask));
    memset(pseudo_mask, 0, sizeof(pseudo_mask));
    memset(add_sec, 0, sizeof(add_sec));
    memset(add_pub, 0, sizeof(add_pub));
    memset(out_amount, 0, sizeof(out_amount));
    memset(nonce, 0, sizeof(nonce));

    // ------------------------------------------------ 1. verify the inputs
    report(cb, user, MW_SIGN_STAGE_VERIFY_INPUTS, 0);
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        mw_tx_source_t* s = &tx->sources[i];
        if (s->ring_size == 0 || s->ring_size > MW_MAX_RING_SIZE ||
            s->real_output_index >= s->ring_size) {
            err = MW_ERR_INVALID_ARG;
            goto done;
        }
        // TZ 8.3: validate every point that came from the file.
        for (uint8_t k = 0; k < s->ring_size; ++k) {
            if (!mw_point_check_public(&s->ring[k].dest) ||
                !mw_point_check_public(&s->ring[k].mask)) {
                err = MW_ERR_SUBGROUP;
                goto done;
            }
        }
        if (!mw_point_check_public(&s->real_out_tx_key)) {
            err = MW_ERR_SUBGROUP;
            goto done;
        }

        err = find_input_secret(keys, tx, s, &in_sec[i]);
        if (err != MW_OK) {
            goto done;                           // MW_ERR_KEY_MISMATCH: not ours
        }

        // The commitment we are about to spend must really open to
        // (mask, amount) or the pseudo-out below would not balance.
        if (!mw_sc_check(&s->mask)) {
            err = MW_ERR_FORMAT;
            goto done;
        }
        const mw_ctkey_t* real = &s->ring[s->real_output_index];
        mw_scalar_t amount_sc;
        amount_to_scalar(s->amount, &amount_sc);
        mw_point_t commitment;
        mw_commit(&commitment, &s->mask, &amount_sc);
        if (!mw_point_eq(&commitment, &real->mask)) {
            err = MW_ERR_BALANCE;
            goto done;
        }

        err = mw_generate_key_image(&real->dest, &in_sec[i], &s->key_image);
        if (err != MW_OK) {
            goto done;
        }
        report(cb, user, MW_SIGN_STAGE_VERIFY_INPUTS,
               (int)(1000u * (i + 1u) / tx->n_inputs));
    }

    // A key image twice in one transaction is a double spend the network
    // rejects; catch it here, where the message can still be specific.
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        for (uint8_t j = (uint8_t)(i + 1u); j < tx->n_inputs; ++j) {
            if (mw_point_eq(&tx->sources[i].key_image, &tx->sources[j].key_image)) {
                err = MW_ERR_FORMAT;
                goto done;
            }
        }
    }

    sort_inputs_by_key_image(tx, in_sec);
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        in_mask[i] = tx->sources[i].mask;        // re-read after the sort
    }

    // ------------------------------------------------ 2. output keys
    report(cb, user, MW_SIGN_STAGE_OUTPUT_KEYS, 0);
    {
        // Destination and change check (inputs are matched now): points,
        // hybrid addresses, own-address flags, change rules. The signer runs
        // it itself so it never depends on the caller's review.
        err = mw_tx_check_destinations(keys, tx, NULL);
        if (err != MW_OK) {
            goto done;
        }

        // ---- payment id (construct_tx_with_tx_key, before shuffling) ----
        int pid_kind = PID_NONE;
        uint8_t pid[8];
        uint8_t long_pid[32];
        memset(pid, 0, sizeof(pid));
        err = scan_extra_in(tx, &pid_kind, pid, long_pid);
        if (err != MW_OK) {
            goto done;
        }
        const mw_pubkey_t* pid_view = destination_view_key(tx);

        // ---- shuffle (construct_tx_and_get_tx_key: shuffle_outs = true)
        for (uint8_t i = 0; i < tx->n_outputs; ++i) {
            tx->out_dest[i] = i;
        }
        if (!tx->no_shuffle) {
            for (uint8_t i = (uint8_t)(tx->n_outputs - 1u); i > 0; --i) {
                const uint8_t j = (uint8_t)random_below((uint32_t)i + 1u);
                const uint8_t t = tx->out_dest[i];
                tx->out_dest[i] = tx->out_dest[j];
                tx->out_dest[j] = t;
            }
        }

        // ---- classify_addresses(): change is not a recipient
        uint8_t n_std = 0, n_sub = 0;
        const mw_tx_destination_t* single_sub = NULL;
        for (uint8_t i = 0; i < tx->n_destinations; ++i) {
            const mw_tx_destination_t* d = &tx->destinations[i];
            if (tx->has_change_addr && same_address(&d->addr, &tx->change_addr)) {
                continue;
            }
            bool dup = false;
            for (uint8_t j = 0; j < i; ++j) {
                const mw_tx_destination_t* e = &tx->destinations[j];
                if (tx->has_change_addr && same_address(&e->addr, &tx->change_addr)) {
                    continue;
                }
                if (same_address(&e->addr, &d->addr)) {
                    dup = true;
                    break;
                }
            }
            if (dup) {
                continue;
            }
            if (d->is_subaddress) {
                ++n_sub;
                single_sub = d;
            } else {
                ++n_std;
            }
        }
        const bool need_additional = (n_sub > 0) && (n_std > 0 || n_sub > 1);

        // Hedged transaction secret key.
        {
            uint8_t ctx[32 + 32];
            memcpy(ctx, keys->sec.spend.b, 32);
            memcpy(ctx + 32, tx->sources[0].key_image.b, 32);
            mw_random_hedged_scalar(&tx->tx_secret_key, ctx, sizeof(ctx));
            mw_memzero(ctx, sizeof(ctx));
        }

        // A single-destination transfer to a subaddress: R = r * D.
        if (n_std == 0 && n_sub == 1 && single_sub != NULL) {
            if (mw_point_scalarmult(&tx->tx_public_key, &tx->tx_secret_key,
                                    &single_sub->addr.spend) != 0) {
                err = MW_ERR_FORMAT;
                goto done;
            }
        } else {
            mw_point_scalarmult_base(&tx->tx_public_key, &tx->tx_secret_key);
        }

        // Change of a subaddress account: its spend key carries m(acct, minor).
        mw_scalar_t change_m;
        mw_sc_0(&change_m);
        if (tx->change_verified && (tx->change_major != 0 || tx->change_minor != 0)) {
            mw_get_subaddress_secret_key(&keys->sec.view, tx->change_major,
                                         tx->change_minor, &change_m);
        }

        for (uint8_t i = 0; i < tx->n_outputs; ++i) {
            const mw_tx_destination_t* d = &tx->destinations[tx->out_dest[i]];
            mw_tx_output_t* o = &tx->outputs[i];
            memset(o, 0, sizeof(*o));
            o->amount = d->amount;
            out_amount[i] = d->amount;

            if (need_additional) {
                mw_sc_random(&add_sec[i]);
                if (d->is_subaddress) {
                    if (mw_point_scalarmult(&add_pub[i], &add_sec[i],
                                            &d->addr.spend) != 0) {
                        err = MW_ERR_FORMAT;
                        mw_memzero(&change_m, sizeof(change_m));
                        goto done;
                    }
                } else {
                    mw_point_scalarmult_base(&add_pub[i], &add_sec[i]);
                }
            }

            // to_change also covers wallet2's 0-amount dummy (derivation a*R,
            // as device_default.cpp does); a real change output is built from
            // the device-derived keys only.
            const bool to_change = tx->has_change_addr &&
                                   same_address(&d->addr, &tx->change_addr);
            const bool is_change = (d->kind == MW_DEST_CHANGE);
            if (is_change && (!tx->change_verified ||
                              !same_address(&d->addr, &tx->change_derived))) {
                err = MW_ERR_KEY_MISMATCH;
                mw_memzero(&change_m, sizeof(change_m));
                goto done;
            }
            const mw_pubkey_t* spend = is_change ? &tx->change_derived.spend : &d->addr.spend;
            mw_point_t derivation;
            if (to_change) {
                // Change to ourselves: derivation = a*R.
                err = mw_generate_key_derivation(&tx->tx_public_key,
                                                 &keys->sec.view, &derivation);
            } else {
                const mw_seckey_t* sec = (need_additional && d->is_subaddress)
                                             ? &add_sec[i] : &tx->tx_secret_key;
                err = mw_generate_key_derivation(&d->addr.view, sec, &derivation);
            }
            if (err != MW_OK) {
                mw_memzero(&change_m, sizeof(change_m));
                goto done;
            }

            err = mw_derive_public_key(&derivation, i, spend, &o->out_pubkey);
            if (err != MW_OK) {
                mw_memzero(&derivation, sizeof(derivation));
                mw_memzero(&change_m, sizeof(change_m));
                goto done;
            }

            mw_scalar_t amount_key;
            mw_derivation_to_scalar(&derivation, i, &amount_key);
            mw_ecdh_encode(&amount_key, d->amount, o->ecdh_amount, &out_mask[i]);

            if (tx->use_view_tags) {
                o->has_view_tag = true;
                o->view_tag = derive_view_tag(&derivation, i);
            }

            mw_scalar_t amount_sc;
            amount_to_scalar(d->amount, &amount_sc);
            mw_commit(&o->commitment, &out_mask[i], &amount_sc);
            o->mask = out_mask[i];

            // Our own change: its key image goes back to the online wallet in
            // tx_key_images, so it knows the output is ours once it arrives.
            if (is_change) {
                mw_seckey_t x;
                mw_sc_add(&x, &amount_key, &keys->sec.spend);
                mw_sc_add(&x, &x, &change_m);
                if (mw_generate_key_image(&o->out_pubkey, &x, &tx->out_ki[i]) == MW_OK) {
                    tx->out_ki_valid[i] = true;
                }
                mw_memzero(&x, sizeof(x));
            }

            mw_memzero(&amount_key, sizeof(amount_key));
            mw_memzero(&derivation, sizeof(derivation));
            report(cb, user, MW_SIGN_STAGE_OUTPUT_KEYS,
                   (int)(1000u * (i + 1u) / tx->n_outputs));
        }
        mw_memzero(&change_m, sizeof(change_m));

        // ---- tx_extra: pub key, additional keys, nonce -------------------
        if (pid_kind == PID_SHORT) {
            if (pid_view == NULL) {
                // "Destinations have to have exactly one output to support
                // encrypted payment ids"
                err = MW_ERR_NOT_SUPPORTED;
                goto done;
            }
            err = encrypt_payment_id(pid, pid_view, &tx->tx_secret_key);
            if (err != MW_OK) {
                goto done;
            }
            nonce[0] = TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID;
            memcpy(nonce + 1, pid, 8);
            nonce_len = 9;
        } else if (pid_kind == PID_LONG) {
            nonce[0] = 0x00;
            memcpy(nonce + 1, long_pid, 32);
            nonce_len = 33;
        } else if (tx->n_destinations <= 2 && pid_view != NULL) {
            // "if we have neither long nor short payment id, add a dummy
            // short one" - encrypted zeros, indistinguishable from a real id.
            memset(pid, 0, sizeof(pid));
            err = encrypt_payment_id(pid, pid_view, &tx->tx_secret_key);
            if (err != MW_OK) {
                goto done;
            }
            nonce[0] = TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID;
            memcpy(nonce + 1, pid, 8);
            nonce_len = 9;
        }
        mw_memzero(pid, sizeof(pid));

        err = mw_tx_extra_build(tx, need_additional ? add_pub : NULL,
                                need_additional ? tx->n_outputs : 0,
                                nonce_len ? nonce : NULL, nonce_len);
        if (err != MW_OK) {
            goto done;
        }
    }

    err = mw_tx_check_balance(tx);
    if (err != MW_OK) {
        goto done;
    }

    // ------------------------------------------------ 3. range proof
    report(cb, user, MW_SIGN_STAGE_BULLETPROOF, 0);
    {
        bpp_bridge_t bridge = { cb, user };
        if (cb != NULL) mw_bpp_set_progress_cb(bpp_bridge, &bridge);
        err = mw_bpp_prove(out_amount, out_mask, tx->n_outputs, &out->bpp);
        mw_bpp_set_progress_cb(NULL, NULL);
    }
    if (err != MW_OK) {
        goto done;
    }
    {
        mw_point_t commitments[MW_MAX_OUTPUTS];
        for (uint8_t i = 0; i < tx->n_outputs; ++i) {
            commitments[i] = tx->outputs[i].commitment;
        }
        // TZ 8.3: V[i]*8 must equal outPk[i].mask.
        err = mw_bpp_check_commitments(&out->bpp, commitments, tx->n_outputs);
        if (err != MW_OK) {
            goto done;
        }
    }
    report(cb, user, MW_SIGN_STAGE_BULLETPROOF, 1000);

    // ------------------------------------------------ 4. CLSAG
    report(cb, user, MW_SIGN_STAGE_CLSAG, 0);
    {
        // Pseudo-out masks: free choice except for the last one, which makes
        // sum(pseudo) == sum(out) so the commitments balance.
        mw_scalar_t sum_out, sum_pseudo;
        mw_sc_0(&sum_out);
        mw_sc_0(&sum_pseudo);
        for (uint8_t i = 0; i < tx->n_outputs; ++i) {
            mw_sc_add(&sum_out, &sum_out, &out_mask[i]);
        }
        for (uint8_t i = 0; i + 1u < tx->n_inputs; ++i) {
            mw_sc_random(&pseudo_mask[i]);
            mw_sc_add(&sum_pseudo, &sum_pseudo, &pseudo_mask[i]);
        }
        mw_sc_sub(&pseudo_mask[tx->n_inputs - 1], &sum_out, &sum_pseudo);

        for (uint8_t i = 0; i < tx->n_inputs; ++i) {
            mw_scalar_t amount_sc;
            mw_sc_0(&amount_sc);
            for (int k = 0; k < 8; ++k) {
                amount_sc.b[k] = (uint8_t)((tx->sources[i].amount >> (8 * k)) & 0xff);
            }
            mw_commit(&out->pseudo_outs[i], &pseudo_mask[i], &amount_sc);
        }
        mw_memzero(&sum_out, sizeof(sum_out));
        mw_memzero(&sum_pseudo, sizeof(sum_pseudo));
    }

    // The bulletproof part of the message hash covers A, A1, B, r1, s1, d1 and
    // the L/R vectors - but not V, which the verifier rebuilds from outPk.
    {
        uint8_t bp_blob[6 * 32 + 2 * MW_BPP_MAX_LOG_MN * 32];
        size_t n = 0;
        memcpy(bp_blob + n, out->bpp.A.b, 32);  n += 32;
        memcpy(bp_blob + n, out->bpp.A1.b, 32); n += 32;
        memcpy(bp_blob + n, out->bpp.B.b, 32);  n += 32;
        memcpy(bp_blob + n, out->bpp.r1.b, 32); n += 32;
        memcpy(bp_blob + n, out->bpp.s1.b, 32); n += 32;
        memcpy(bp_blob + n, out->bpp.d1.b, 32); n += 32;
        for (uint8_t i = 0; i < out->bpp.n_lr; ++i) {
            memcpy(bp_blob + n, out->bpp.L[i].b, 32);
            n += 32;
        }
        for (uint8_t i = 0; i < out->bpp.n_lr; ++i) {
            memcpy(bp_blob + n, out->bpp.R[i].b, 32);
            n += 32;
        }
        err = mw_tx_prefix_hash(tx, out->prefix_hash);
        if (err != MW_OK) {
            goto done;
        }
        err = mw_tx_rct_message(tx, bp_blob, n, out->message);
        if (err != MW_OK) {
            goto done;
        }
    }

    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        const mw_tx_source_t* s = &tx->sources[i];
        mw_scalar_t z;
        mw_sc_sub(&z, &in_mask[i], &pseudo_mask[i]);   // real mask - pseudo mask
        err = mw_clsag_sign(out->message, s->ring, s->ring_size,
                            s->real_output_index, &in_sec[i], &z,
                            &out->pseudo_outs[i], &s->key_image, &out->clsag[i]);
        mw_memzero(&z, sizeof(z));
        if (err != MW_OK) {
            goto done;
        }
        report(cb, user, MW_SIGN_STAGE_CLSAG,
               (int)(1000u * (i + 1u) / tx->n_inputs));
    }

    report(cb, user, MW_SIGN_STAGE_SERIALIZE, 0);
    report(cb, user, MW_SIGN_STAGE_DONE, 1000);

done:
    mw_memzero(in_sec, sizeof(in_sec));
    mw_memzero(nonce, sizeof(nonce));
    mw_memzero(in_mask, sizeof(in_mask));
    mw_memzero(out_mask, sizeof(out_mask));
    mw_memzero(pseudo_mask, sizeof(pseudo_mask));
    mw_memzero(add_sec, sizeof(add_sec));
    if (err != MW_OK) {
        mw_memzero(out, sizeof(*out));
    }
    return err;
}

// --------------------------------------------------------------- RCT blob
// rctSigBase (type 6) followed by rctSigPrunable:
//     type(1) varint(fee) ecdhInfo(8 per output) outPk.mask(32 per output)
//     varint(#bp = 1) bulletproof_plus
//     per input: s[ring_size] c1 D            (I is rebuilt from the input)
//     per input: pseudoOut
size_t mw_serialize_rct(const mw_transaction_t* tx, const mw_signed_data_t* sd,
                        uint8_t* out, size_t out_cap)
{
    if (tx == NULL || sd == NULL) {
        return 0;
    }
    if (tx->n_inputs == 0 || tx->n_inputs > MW_MAX_INPUTS ||
        tx->n_outputs == 0 || tx->n_outputs > MW_MAX_OUTPUTS) {
        return 0;
    }

    if (out == NULL) {
        size_t n = 1 + mw_varint_size(tx->fee) + (size_t)tx->n_outputs * (8 + 32);
        n += mw_varint_size(1);
        n += 6 * 32 + mw_varint_size(sd->bpp.n_lr) + (size_t)sd->bpp.n_lr * 32 +
             mw_varint_size(sd->bpp.n_lr) + (size_t)sd->bpp.n_lr * 32;
        for (uint8_t i = 0; i < tx->n_inputs; ++i) {
            n += (size_t)sd->clsag[i].n * 32 + 64;
        }
        n += (size_t)tx->n_inputs * 32;
        return n;
    }

    mw_writer_t w;
    mw_writer_init(&w, out, out_cap);

    mw_write_u8(&w, tx->rct_type);
    mw_write_varint(&w, tx->fee);
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        mw_write_bytes(&w, tx->outputs[i].ecdh_amount, 8);
    }
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        mw_write_point(&w, &tx->outputs[i].commitment);
    }

    mw_write_varint(&w, 1);                      // exactly one BP+ proof
    {
        uint8_t buf[6 * 32 + 2 * (MW_BPP_MAX_LOG_MN * 32 + 10)];
        size_t n = mw_bpp_serialize(&sd->bpp, buf, sizeof(buf));
        if (n == 0) {
            return 0;
        }
        mw_write_bytes(&w, buf, n);
    }

    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        const mw_clsag_t* c = &sd->clsag[i];
        if (c->n != tx->sources[i].ring_size) {
            return 0;
        }
        for (uint8_t k = 0; k < c->n; ++k) {
            mw_write_scalar(&w, &c->s[k]);
        }
        mw_write_scalar(&w, &c->c1);
        mw_write_point(&w, &c->D);
    }
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        mw_write_point(&w, &sd->pseudo_outs[i]);
    }

    return w.overflow ? 0 : w.pos;
}
