// End-to-end transaction signing (TZ 12.2) and the confirmation summary
// (TZ 12.3).
//
// Until this suite existed, src/monero/sign.c, src/monero/tx.c and the
// transaction half of src/monero/file_formats.c were compiled but never
// executed by any test, so two of the five TZ 8.3 validation requirements -
// the balance check and V[i]*8 == outPk[i].mask - were unverified end to end.
//
// The fixture builds a synthetic but fully consistent transaction: two inputs
// with a ring of 16 each, two destinations (one external, one change back to
// the signing account). "Consistent" means the same thing the signer re-derives
// from the account keys:
//
//     ring[real].dest = Hs(8*a*R || i)*G + B      (our one-time output)
//     ring[real].mask = mask*G + amount*H         (its commitment)
//
// so mw_sign_transaction() can re-derive the one-time secret, match the key
// image and open the commitment exactly as it would for a real wallet2 file.
#include "test_framework.h"

#include "monero/address.h"
#include "monero/bulletproof_plus.h"
#include "monero/clsag.h"
#include "monero/file_formats.h"
#include "monero/keys.h"
#include "monero/key_image.h"
#include "monero/serialize.h"
#include "monero/sign.h"
#include "monero/tx.h"
#include "crypto/ed25519.h"
#include "crypto/hash.h"
#include "crypto/random.h"

#define RING          MW_RING_SIZE      // 16
#define IN0_AMOUNT    3000000000000ULL  // 3 XMR
#define IN1_AMOUNT    2000000000000ULL  // 2 XMR
#define SEND_AMOUNT   4000000000000ULL  // 4 XMR to the external recipient
#define TX_FEE          30000000000ULL  // 0.03 XMR
#define CHANGE_AMOUNT (IN0_AMOUNT + IN1_AMOUNT - SEND_AMOUNT - TX_FEE)

// Scratch big enough for anything this fixture produces; static so the
// 45 KB mw_transaction_t never lands on a small stack.
static mw_transaction_t   g_tx;
static mw_signed_data_t   g_sd;
static mw_account_keys_t  g_keys;
static uint8_t            g_rct[8192];
static uint8_t            g_raw[16384];

// ---------------------------------------------------------------- helpers
static void amount_scalar(uint64_t v, mw_scalar_t* s)
{
    mw_sc_0(s);
    for (int i = 0; i < 8; ++i) {
        s->b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    }
}

static void test_account(mw_account_keys_t* keys)
{
    uint8_t seed[32];
    mw_test_hex("3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109",
                seed, sizeof seed);
    mw_keys_from_legacy_seed(seed, keys);
    CHECK_EQ_INT(mw_keys_derive_public(keys), MW_OK);
}

// A random but valid public point (k*G, k != 0), i.e. something that passes
// mw_point_check_public().
static void random_point(mw_point_t* p)
{
    mw_scalar_t k;
    mw_sc_random(&k);
    mw_point_scalarmult_base(p, &k);
}

// Fills one input: a ring of `RING` decoys with our real output at `real_idx`.
static void make_source(mw_tx_source_t* s, const mw_account_keys_t* keys,
                        uint64_t amount, uint8_t real_idx, uint32_t out_in_tx)
{
    memset(s, 0, sizeof(*s));
    s->ring_size = RING;
    s->real_output_index = real_idx;
    s->real_output_in_tx_index = out_in_tx;
    s->amount = amount;

    for (uint8_t k = 0; k < RING; ++k) {
        mw_scalar_t m, a;
        random_point(&s->ring[k].dest);
        mw_sc_random(&m);
        amount_scalar(1000u + k, &a);
        mw_commit(&s->ring[k].mask, &m, &a);
        // Strictly increasing global indices -> sane relative offsets.
        s->key_offsets[k] = (k == 0) ? (1000u + 37u * real_idx) : (1u + k);
    }

    // The real member, built exactly as the sending wallet built it.
    mw_scalar_t r;
    mw_sc_random(&r);
    mw_point_scalarmult_base(&s->real_out_tx_key, &r);

    mw_point_t derivation;
    CHECK_EQ_INT(mw_generate_key_derivation(&s->real_out_tx_key, &keys->sec.view,
                                            &derivation), MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&derivation, out_in_tx, &keys->pub.spend,
                                      &s->ring[real_idx].dest), MW_OK);

    mw_scalar_t amt;
    mw_sc_random(&s->mask);
    amount_scalar(amount, &amt);
    mw_commit(&s->ring[real_idx].mask, &s->mask, &amt);
}

// Two inputs, two destinations (external + change). tx_extra is left empty:
// mw_sign_transaction() builds it from the transaction key it picks.
static void build_tx(mw_transaction_t* tx, const mw_account_keys_t* keys)
{
    memset(tx, 0, sizeof(*tx));
    tx->version     = 2;
    tx->unlock_time = 0;
    tx->rct_type    = 6;                       // RCTTypeBulletproofPlus
    tx->use_view_tags = true;
    tx->fee         = TX_FEE;
    tx->n_inputs    = 2;

    make_source(&tx->sources[0], keys, IN0_AMOUNT, 5, 1);
    make_source(&tx->sources[1], keys, IN1_AMOUNT, 11, 0);

    // Destination 0: someone else's standard address.
    mw_scalar_t b, a;
    mw_sc_random(&b);
    mw_sc_random(&a);
    memset(&tx->destinations[0], 0, sizeof(tx->destinations[0]));
    mw_point_scalarmult_base(&tx->destinations[0].addr.spend, &b);
    mw_point_scalarmult_base(&tx->destinations[0].addr.view, &a);
    tx->destinations[0].addr.type = MW_ADDR_STANDARD;
    tx->destinations[0].amount    = SEND_AMOUNT;

    // Destination 1: change, back to our own primary address.
    memset(&tx->destinations[1], 0, sizeof(tx->destinations[1]));
    tx->destinations[1].addr.spend = keys->pub.spend;
    tx->destinations[1].addr.view  = keys->pub.view;
    tx->destinations[1].addr.type  = MW_ADDR_STANDARD;
    tx->destinations[1].amount     = CHANGE_AMOUNT;

    tx->n_destinations   = 2;
    tx->n_outputs        = 2;
    // change_dts of the construction data: our primary address. is_change is
    // decided by mw_tx_check_destinations(), never set by the file.
    tx->has_change_addr  = true;
    tx->change_addr      = tx->destinations[1].addr;
    tx->change_amount    = CHANGE_AMOUNT;
    // Deterministic output order for the assertions below; the shuffle has
    // its own test.
    tx->no_shuffle       = true;
}

// What the review does before mw_tx_check_destinations(): match every input
// to its subaddress.
static void match_inputs(mw_transaction_t* tx)
{
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        mw_keyimage_t ki;
        CHECK_EQ_INT(mw_sign_input_key_image(&g_keys, tx, i, &ki), MW_OK);
    }
}

// The review path: match, check, summarize.
static mw_err_t review_tx(mw_transaction_t* tx, mw_tx_summary_t* sum)
{
    match_inputs(tx);
    mw_err_t e = mw_tx_check_destinations(&g_keys, tx, NULL);
    if (e != MW_OK) return e;
    return mw_tx_summarize(tx, MW_NET_MAINNET, sum);
}

// r = sum(points)
static void point_sum(mw_point_t* r, const mw_point_t* pts, uint8_t n)
{
    CHECK(n > 0);
    *r = pts[0];
    for (uint8_t i = 1; i < n; ++i) {
        CHECK_EQ_INT(mw_point_add(r, r, &pts[i]), 0);
    }
}

// ------------------------------------------------------------- happy path
MW_TEST(test_sign_two_inputs_two_outputs)
{
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);

    CHECK_EQ_INT(g_tx.n_outputs, 2);
    CHECK_EQ_INT(mw_tx_check_balance(&g_tx), MW_OK);

    // ---- every CLSAG must verify against the message that was produced ----
    for (uint8_t i = 0; i < g_tx.n_inputs; ++i) {
        const mw_tx_source_t* s = &g_tx.sources[i];
        CHECK_EQ_INT(g_sd.clsag[i].n, s->ring_size);
        CHECK_EQ_INT(mw_clsag_verify(g_sd.message, s->ring, s->ring_size,
                                     &g_sd.pseudo_outs[i], &s->key_image,
                                     &g_sd.clsag[i]), MW_OK);
        // ... and only against that message.
        uint8_t other[32];
        memcpy(other, g_sd.message, 32);
        other[0] ^= 0x01u;
        CHECK(mw_clsag_verify(other, s->ring, s->ring_size, &g_sd.pseudo_outs[i],
                              &s->key_image, &g_sd.clsag[i]) != MW_OK);
    }

    // Inputs leave sorted by key image, descending, as construct_tx does.
    for (uint8_t i = 1; i < g_tx.n_inputs; ++i) {
        CHECK(memcmp(g_tx.sources[i - 1].key_image.b,
                     g_tx.sources[i].key_image.b, 32) > 0);
    }

    // ---- the range proof ----
    CHECK_EQ_INT(mw_bpp_verify(&g_sd.bpp), MW_OK);
    CHECK_EQ_INT(g_sd.bpp.n_v, g_tx.n_outputs);

    // TZ 8.3: V[i]*8 == outPk[i].mask. Checked here independently of
    // mw_bpp_check_commitments(), which is the function under test inside the
    // signer - V is serialized divided by the cofactor, so the verifier
    // multiplies it back up.
    {
        mw_scalar_t eight;
        mw_sc_0(&eight);
        eight.b[0] = 8;
        for (uint8_t i = 0; i < g_tx.n_outputs; ++i) {
            mw_point_t v8;
            CHECK_EQ_INT(mw_point_scalarmult(&v8, &eight, &g_sd.bpp.V[i]), 0);
            CHECK_EQ_MEM(v8.b, g_tx.outputs[i].commitment.b, 32);
        }
    }

    // ---- commitments balance on the curve ----
    // rct::verRctSemanticsSimple(): sum(pseudoOuts) == sum(outPk.mask) + fee*H.
    // The fee term is not optional - the fee is the one amount a RingCT
    // transaction carries in the clear, so it appears on the output side as a
    // commitment to (0, fee). Dropping it only holds for a zero-fee
    // transaction, which test_sign_zero_fee_balances below covers separately.
    {
        mw_point_t sum_pseudo, sum_out, fee_h, want;
        mw_point_t out_masks[MW_MAX_OUTPUTS];
        mw_scalar_t fee_sc;

        for (uint8_t i = 0; i < g_tx.n_outputs; ++i) {
            out_masks[i] = g_tx.outputs[i].commitment;
        }
        point_sum(&sum_pseudo, g_sd.pseudo_outs, g_tx.n_inputs);
        point_sum(&sum_out, out_masks, g_tx.n_outputs);

        amount_scalar(g_tx.fee, &fee_sc);
        mw_scalarmult_H(&fee_h, &fee_sc);
        CHECK_EQ_INT(mw_point_add(&want, &sum_out, &fee_h), 0);
        CHECK_EQ_MEM(sum_pseudo.b, want.b, 32);
    }

    // ---- the two prefix serialisers must agree ----
    // mw_tx_prefix_hash() streams the prefix into Keccak while
    // mw_build_signed_tx() writes the same prefix into a buffer; they are two
    // separate pieces of code, so the hash is recomputed over the bytes that
    // actually leave the device.
    {
        size_t rct_len = mw_serialize_rct(&g_tx, &g_sd, g_rct, sizeof g_rct);
        CHECK(rct_len > 0);
        CHECK_EQ_INT((int)mw_serialize_rct(&g_tx, &g_sd, NULL, 0), (int)rct_len);

        size_t raw_len = 0;
        CHECK_EQ_INT(mw_build_signed_tx(&g_tx, g_rct, rct_len, g_raw,
                                        sizeof g_raw, &raw_len), MW_OK);
        CHECK(raw_len > rct_len);

        size_t query = 0;
        CHECK_EQ_INT(mw_build_signed_tx(&g_tx, g_rct, rct_len, NULL, 0, &query),
                     MW_OK);
        CHECK_EQ_INT((int)query, (int)raw_len);

        const size_t prefix_len = raw_len - rct_len;
        uint8_t recomputed[32];
        mw_keccak256(g_raw, prefix_len, recomputed);
        CHECK_EQ_MEM(recomputed, g_sd.prefix_hash, 32);

        uint8_t direct[32];
        CHECK_EQ_INT(mw_tx_prefix_hash(&g_tx, direct), MW_OK);
        CHECK_EQ_MEM(direct, g_sd.prefix_hash, 32);

        // The RCT blob is appended verbatim.
        CHECK_EQ_MEM(g_raw + prefix_len, g_rct, rct_len);
    }

    // ---- the message really is keccak(prefix || base || bp) ----
    {
        uint8_t bp_blob[6 * 32 + 2 * MW_BPP_MAX_LOG_MN * 32];
        size_t n = 0;
        memcpy(bp_blob + n, g_sd.bpp.A.b, 32);  n += 32;
        memcpy(bp_blob + n, g_sd.bpp.A1.b, 32); n += 32;
        memcpy(bp_blob + n, g_sd.bpp.B.b, 32);  n += 32;
        memcpy(bp_blob + n, g_sd.bpp.r1.b, 32); n += 32;
        memcpy(bp_blob + n, g_sd.bpp.s1.b, 32); n += 32;
        memcpy(bp_blob + n, g_sd.bpp.d1.b, 32); n += 32;
        for (uint8_t i = 0; i < g_sd.bpp.n_lr; ++i) {
            memcpy(bp_blob + n, g_sd.bpp.L[i].b, 32);
            n += 32;
        }
        for (uint8_t i = 0; i < g_sd.bpp.n_lr; ++i) {
            memcpy(bp_blob + n, g_sd.bpp.R[i].b, 32);
            n += 32;
        }
        uint8_t msg[32];
        CHECK_EQ_INT(mw_tx_rct_message(&g_tx, bp_blob, n, msg), MW_OK);
        CHECK_EQ_MEM(msg, g_sd.message, 32);
    }

    // ---- the outputs are spendable by their recipients ----
    // Change comes back to us: the one-time key must be re-derivable with our
    // own view key, which is what makes the change actually recoverable.
    {
        mw_point_t derivation;
        CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.tx_public_key,
                                                &g_keys.sec.view, &derivation),
                     MW_OK);
        mw_pubkey_t expect;
        CHECK_EQ_INT(mw_derive_public_key(&derivation, 1, &g_keys.pub.spend,
                                          &expect), MW_OK);
        CHECK_EQ_MEM(expect.b, g_tx.outputs[1].out_pubkey.b, 32);

        // The masked amount decodes back to the change we intended.
        mw_scalar_t amount_key;
        mw_derivation_to_scalar(&derivation, 1, &amount_key);
        uint64_t amount = 0;
        mw_ecdh_mask_t mask;
        memcpy(&amount, g_tx.outputs[1].ecdh_amount, 8);
        mw_ecdh_decode(&amount_key, &amount, &mask);
        CHECK_EQ_INT((long long)amount, (long long)CHANGE_AMOUNT);
        CHECK_EQ_MEM(mask.b, g_tx.outputs[1].mask.b, 32);
    }

    // tx_extra must carry the transaction public key the outputs were built
    // from, or no wallet can ever find them.
    CHECK(g_tx.tx_extra_len >= 33);
    CHECK_EQ_INT(g_tx.tx_extra[0], 0x01);
    CHECK_EQ_MEM(g_tx.tx_extra + 1, g_tx.tx_public_key.b, 32);
}

// The plain "sum(pseudo_outs) == sum(outPk.mask)" identity, which only holds
// when there is no fee to account for.
MW_TEST(test_sign_zero_fee_balances)
{
    build_tx(&g_tx, &g_keys);
    g_tx.fee = 0;
    g_tx.destinations[1].amount = IN0_AMOUNT + IN1_AMOUNT - SEND_AMOUNT;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);

    mw_point_t sum_pseudo, sum_out;
    mw_point_t out_masks[MW_MAX_OUTPUTS];
    for (uint8_t i = 0; i < g_tx.n_outputs; ++i) {
        out_masks[i] = g_tx.outputs[i].commitment;
    }
    point_sum(&sum_pseudo, g_sd.pseudo_outs, g_tx.n_inputs);
    point_sum(&sum_out, out_masks, g_tx.n_outputs);
    CHECK_EQ_MEM(sum_pseudo.b, sum_out.b, 32);

    for (uint8_t i = 0; i < g_tx.n_inputs; ++i) {
        CHECK_EQ_INT(mw_clsag_verify(g_sd.message, g_tx.sources[i].ring,
                                     g_tx.sources[i].ring_size,
                                     &g_sd.pseudo_outs[i],
                                     &g_tx.sources[i].key_image,
                                     &g_sd.clsag[i]), MW_OK);
    }
    CHECK_EQ_INT(mw_bpp_verify(&g_sd.bpp), MW_OK);
}

// --------------------------------------------------------- negative cases
MW_TEST(test_sign_rejects_unbalanced_amounts)
{
    // TZ 8.3: inputs must equal outputs + fee. Bumping one destination by a
    // single atomic unit is the cheapest way an altered file could try to
    // steal - the signer has to refuse before any proof is produced.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].amount += 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_BALANCE);

    build_tx(&g_tx, &g_keys);
    g_tx.fee += 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_BALANCE);

    // An input whose commitment does not open to (mask, amount) is the same
    // class of failure, caught while the inputs are verified.
    build_tx(&g_tx, &g_keys);
    g_tx.sources[0].amount += 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_BALANCE);

    // mw_tx_check_balance() on its own.
    build_tx(&g_tx, &g_keys);
    g_tx.outputs[0].amount = SEND_AMOUNT;
    g_tx.outputs[1].amount = CHANGE_AMOUNT;
    CHECK_EQ_INT(mw_tx_check_balance(&g_tx), MW_OK);
    g_tx.outputs[1].amount -= 1;
    CHECK_EQ_INT(mw_tx_check_balance(&g_tx), MW_ERR_BALANCE);
    g_tx.outputs[1].amount = UINT64_MAX;
    CHECK_EQ_INT(mw_tx_check_balance(&g_tx), MW_ERR_RANGE);
}

MW_TEST(test_sign_rejects_low_order_ring_point)
{
    // Canonical order-8 point: a valid curve point outside the prime-order
    // subgroup. Every point read from the unsigned tx set has to be checked.
    static const char* const low_order[] = {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    };
    const size_t n_low = sizeof(low_order) / sizeof(low_order[0]);

    for (size_t k = 0; k < n_low; ++k) {
        mw_point_t bad;
        CHECK_EQ_INT((int)mw_test_hex(low_order[k], bad.b, 32), 32);
        CHECK_EQ_INT(mw_point_check_public(&bad), 0);

        // ... as a decoy's one-time key ...
        build_tx(&g_tx, &g_keys);
        g_tx.sources[0].ring[3].dest = bad;
        CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                     MW_ERR_SUBGROUP);

        // ... as a decoy's commitment ...
        build_tx(&g_tx, &g_keys);
        g_tx.sources[1].ring[9].mask = bad;
        CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                     MW_ERR_SUBGROUP);

        // ... as the source transaction's public key ...
        build_tx(&g_tx, &g_keys);
        g_tx.sources[0].real_out_tx_key = bad;
        CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                     MW_ERR_SUBGROUP);

        // ... and as a destination key.
        build_tx(&g_tx, &g_keys);
        g_tx.destinations[0].addr.view = bad;
        CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                     MW_ERR_SUBGROUP);
    }
}

MW_TEST(test_sign_rejects_foreign_real_output)
{
    // The "real" ring member does not belong to this account: the one-time
    // secret the signer re-derives cannot open it, so x*G != P.
    build_tx(&g_tx, &g_keys);
    random_point(&g_tx.sources[0].ring[g_tx.sources[0].real_output_index].dest);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);

    // Same thing seen from the other side: a source transaction key that is
    // not the one our output was created with.
    build_tx(&g_tx, &g_keys);
    random_point(&g_tx.sources[1].real_out_tx_key);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);

    // A wrong output index inside the source transaction derives a different
    // one-time key as well.
    build_tx(&g_tx, &g_keys);
    g_tx.sources[0].real_output_in_tx_index += 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);

    // Change that is not ours must be refused too, or the signer would happily
    // hand the "change" to somebody else.
    build_tx(&g_tx, &g_keys);
    random_point(&g_tx.destinations[1].addr.spend);
    g_tx.change_addr = g_tx.destinations[1].addr;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);
}

MW_TEST(test_sign_rejects_bad_arguments)
{
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_sign_transaction(NULL, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, NULL, &g_sd, NULL, NULL),
                 MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, NULL, NULL, NULL),
                 MW_ERR_INVALID_ARG);

    // A view-only wallet has no spend key and must refuse early (TZ 4.2).
    {
        mw_account_keys_t view_only = g_keys;
        view_only.view_only = true;
        CHECK_EQ_INT(mw_sign_transaction(&view_only, &g_tx, &g_sd, NULL, NULL),
                     MW_ERR_NOT_SUPPORTED);
    }

    // Only RCTTypeBulletproofPlus is signed.
    build_tx(&g_tx, &g_keys);
    g_tx.rct_type = 5;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_NOT_SUPPORTED);

    build_tx(&g_tx, &g_keys);
    g_tx.n_inputs = 0;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_TOO_MANY);

    build_tx(&g_tx, &g_keys);
    g_tx.n_destinations = 0;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_TOO_MANY);

    build_tx(&g_tx, &g_keys);
    g_tx.sources[0].ring_size = MW_MAX_RING_SIZE + 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_INVALID_ARG);

    build_tx(&g_tx, &g_keys);
    g_tx.sources[0].real_output_index = g_tx.sources[0].ring_size;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_INVALID_ARG);
}

// ------------------------------------------------------ progress reporting
static int g_stage_seen[MW_SIGN_STAGE_DONE + 1];

static void progress_cb(mw_sign_stage_t stage, int permille, void* user)
{
    (void)user;
    if (stage <= MW_SIGN_STAGE_DONE && permille >= 0 && permille <= 1000) {
        g_stage_seen[stage]++;
    }
}

MW_TEST(test_sign_reports_every_stage)
{
    memset(g_stage_seen, 0, sizeof g_stage_seen);
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, progress_cb, NULL),
                 MW_OK);
    for (int s = 0; s <= MW_SIGN_STAGE_DONE; ++s) {
        CHECK(g_stage_seen[s] > 0);
    }
}

// ------------------------------------------------------------ the summary
MW_TEST(test_summary_totals)
{
    mw_tx_summary_t sum;

    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK_EQ_INT((long long)sum.total_in, (long long)(IN0_AMOUNT + IN1_AMOUNT));
    CHECK_EQ_INT((long long)sum.total_out, (long long)SEND_AMOUNT);
    CHECK_EQ_INT((long long)sum.change, (long long)CHANGE_AMOUNT);
    CHECK_EQ_INT((long long)sum.fee, (long long)TX_FEE);
    CHECK_EQ_INT(sum.n_inputs, 2);
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK_EQ_INT((long long)sum.amounts[0], (long long)SEND_AMOUNT);
    CHECK_EQ_INT((int)strlen(sum.recipients[0]), 95);

    // The recipient string is re-encoded from the keys that will be paid.
    {
        mw_address_t expect;
        char str[MW_ADDRESS_STR_MAX];
        memset(&expect, 0, sizeof expect);
        expect.spend   = g_tx.destinations[0].addr.spend;
        expect.view    = g_tx.destinations[0].addr.view;
        expect.type    = MW_ADDR_STANDARD;
        expect.network = MW_NET_MAINNET;
        CHECK_EQ_INT(mw_address_encode(&expect, str, sizeof str), MW_OK);
        CHECK_EQ_STR(sum.recipients[0], str);
    }

    // Subaddress destinations keep their own prefix.
    g_tx.destinations[0].is_subaddress = true;
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_OK);
    CHECK_EQ_INT(sum.recipients[0][0], '8');

    CHECK_EQ_INT(mw_tx_summarize(NULL, MW_NET_MAINNET, &sum), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, NULL), MW_ERR_INVALID_ARG);

    // A bare is_change (not set by the check) is never trusted.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[1].is_change = true;
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_ERR_INVALID_ARG);
    // Nor a CHANGE row whose keys differ from the re-derived change.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    random_point(&g_tx.change_derived.spend);
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_ERR_INVALID_ARG);
}

// Bug 3: the change is shown with its address, re-derived by the device.
MW_TEST(test_change_shown_main)
{
    mw_tx_summary_t sum;
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.has_change);
    CHECK_EQ_INT((int)sum.change_major, 0);
    CHECK_EQ_INT((int)sum.change_minor, 0);
    CHECK_EQ_INT((long long)sum.change, (long long)CHANGE_AMOUNT);
    mw_address_t main_addr;
    char str[MW_ADDRESS_STR_MAX];
    CHECK_EQ_INT(mw_address_from_keys(&g_keys, MW_NET_MAINNET, &main_addr), MW_OK);
    CHECK_EQ_INT(mw_address_encode(&main_addr, str, sizeof str), MW_OK);
    CHECK_EQ_STR(sum.change_addr, str);
    CHECK_EQ_INT((int)strlen(sum.change_addr), 95);
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK(!sum.recipient_own[0]);
    CHECK_EQ_INT(sum.n_dummy, 0);
    CHECK(sum.high_fee);                 // the fixture's 0.03 XMR > 0.01 XMR

    // A normal fee (0.00003 XMR) is not flagged.
    build_tx(&g_tx, &g_keys);
    g_tx.fee = 30000000ULL;
    g_tx.destinations[1].amount += TX_FEE - g_tx.fee;
    g_tx.change_amount = g_tx.destinations[1].amount;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(!sum.high_fee);
    // 10% of what moves is the other bound.
    g_tx.fee = (SEND_AMOUNT + g_tx.change_amount) / 10u + 1u;
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_OK);
    CHECK(sum.high_fee);

    // Network-aware: the same change on stagenet starts with '5'.
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_STAGENET, &sum), MW_OK);
    CHECK_EQ_INT(sum.change_addr[0], '5');

    // No change_dts at all: "no change", and the dropped change becomes fee,
    // which the high-fee flag reports.
    build_tx(&g_tx, &g_keys);
    g_tx.has_change_addr = false;
    g_tx.change_amount = 0;
    g_tx.n_destinations = 1;
    g_tx.fee += CHANGE_AMOUNT;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(!sum.has_change);
    CHECK_EQ_INT(sum.change_addr[0], 0);
    CHECK(sum.high_fee);
}

static void make_subaddress_source(mw_tx_source_t* s, const mw_account_keys_t* keys,
                                   uint64_t amount, uint32_t major, uint32_t minor);

// Both inputs in account `acct` (minors m0, m1), change to (acct, 0).
static void build_account_tx(uint32_t acct, uint32_t m0, uint32_t m1)
{
    build_tx(&g_tx, &g_keys);
    make_subaddress_source(&g_tx.sources[0], &g_keys, IN0_AMOUNT, acct, m0);
    make_subaddress_source(&g_tx.sources[1], &g_keys, IN1_AMOUNT, acct, m1);
    g_tx.subaddr_account = acct;
    g_tx.subaddr_hints[0] = m0;
    g_tx.subaddr_hints[1] = m1;
    g_tx.n_subaddr_hints = 2;
    mw_address_t sub;
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, acct, 0, &sub), MW_OK);
    g_tx.destinations[1].addr = sub;
    g_tx.destinations[1].is_subaddress = (acct != 0);
    g_tx.change_addr = sub;
    g_tx.change_is_subaddress = (acct != 0);
}

MW_TEST(test_change_shown_subaccount)
{
    mw_tx_summary_t sum;
    build_account_tx(2, 3, 7);
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.has_change);
    CHECK_EQ_INT((int)sum.change_major, 2);
    CHECK_EQ_INT((int)sum.change_minor, 0);
    CHECK_EQ_INT(sum.change_addr[0], '8');
    {
        mw_address_t sub;
        char str[MW_ADDRESS_STR_MAX];
        CHECK_EQ_INT(mw_get_subaddress(&g_keys, 2, 0, &sub), MW_OK);
        sub.network = MW_NET_MAINNET;
        sub.type = MW_ADDR_SUBADDRESS;
        CHECK_EQ_INT(mw_address_encode(&sub, str, sizeof str), MW_OK);
        CHECK_EQ_STR(sum.change_addr, str);
    }
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    CHECK(g_tx.out_ki_valid[1]);
    CHECK(!g_tx.out_ki_valid[0]);
    mw_seckey_t x;
    CHECK_EQ_INT(mw_output_secret(&g_keys, &g_tx.outputs[1].out_pubkey, &g_tx.tx_public_key,
                                  NULL, 1, 2, 0, &x), MW_OK);
    mw_keyimage_t ki;
    CHECK_EQ_INT(mw_generate_key_image(&g_tx.outputs[1].out_pubkey, &x, &ki), MW_OK);
    CHECK_EQ_MEM(ki.b, g_tx.out_ki[1].b, 32);
}

// Expects the check AND the signer to refuse with `reason`.
static void expect_refused(uint8_t reason)
{
    static mw_transaction_t copy;
    static const mw_signed_data_t zero;
    copy = g_tx;
    match_inputs(&g_tx);
    mw_tx_check_info_t ci;
    memset(&ci, 0, sizeof ci);
    CHECK(mw_tx_check_destinations(&g_keys, &g_tx, &ci) != MW_OK);
    CHECK_EQ_INT(ci.reason, reason);
    for (uint8_t i = 0; i < g_tx.n_destinations; ++i) {
        CHECK(!g_tx.destinations[i].is_change);
        CHECK_EQ_INT(g_tx.destinations[i].kind, MW_DEST_FOREIGN);
    }
    CHECK(!g_tx.change_verified);
    memset(&g_sd, 0xA5, sizeof g_sd);
    CHECK(mw_sign_transaction(&g_keys, &copy, &g_sd, NULL, NULL) != MW_OK);
    CHECK_EQ_INT(copy.check.reason, reason);
    CHECK(memcmp(&g_sd, &zero, sizeof g_sd) == 0);
}

// A copy of `a` with one half replaced.
static void hybrid(mw_address_t* out, const mw_point_t* spend, const mw_point_t* view)
{
    memset(out, 0, sizeof *out);
    out->spend = *spend;
    out->view = *view;
}

// Bug 5: half-ours addresses, in every placement.
MW_TEST(test_hybrid_destinations_refused)
{
    mw_point_t b_att, a_att, d_att, ad_att;
    mw_address_t acct2;
    random_point(&b_att);
    random_point(&a_att);
    random_point(&d_att);
    CHECK_EQ_INT(mw_point_scalarmult(&ad_att, &g_keys.sec.view, &d_att), 0);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 2, 0, &acct2), MW_OK);

    struct { mw_address_t a; bool sub; uint8_t reason; uint32_t acct; } h[7];
    hybrid(&h[0].a, &b_att, &g_keys.pub.view);   h[0].sub = false;
    h[0].reason = MW_TXR_HYBRID_OUR_VIEW;        h[0].acct = 0;
    h[1] = h[0];                                 h[1].sub = true;
    hybrid(&h[2].a, &d_att, &ad_att);            h[2].sub = true;
    h[2].reason = MW_TXR_HYBRID_VIEW_LINKED;     h[2].acct = 0;
    h[3] = h[2];                                 h[3].sub = false;
    hybrid(&h[4].a, &g_keys.pub.spend, &a_att);  h[4].sub = false;
    h[4].reason = MW_TXR_HYBRID_OUR_SPEND;       h[4].acct = 0;
    hybrid(&h[5].a, &acct2.spend, &a_att);       h[5].sub = true;
    h[5].reason = MW_TXR_HYBRID_OUR_SPEND;       h[5].acct = 2;
    hybrid(&h[6].a, &a_att, &acct2.view);        h[6].sub = true;   // X2-like
    h[6].reason = MW_TXR_HYBRID_OUR_VIEW;        h[6].acct = 2;

    for (int k = 0; k < 7; ++k) {
        for (int place = 0; place < 4; ++place) {
            if (h[k].acct) build_account_tx(h[k].acct, 3, 7);
            else build_tx(&g_tx, &g_keys);
            mw_tx_destination_t* d0 = &g_tx.destinations[0];
            switch (place) {
            case 0:                                   // ordinary, no change_dts
                d0->addr = h[k].a;
                d0->is_subaddress = h[k].sub;
                g_tx.has_change_addr = false;
                break;
            case 1:                                   // ordinary next to change
                d0->addr = h[k].a;
                d0->is_subaddress = h[k].sub;
                break;
            case 2:                                   // declared change pays it
                g_tx.destinations[1].addr = h[k].a;
                g_tx.destinations[1].is_subaddress = h[k].sub;
                g_tx.change_addr = h[k].a;
                break;
            default:                                  // a zero-amount extra output
                g_tx.destinations[2] = *d0;
                g_tx.destinations[2].addr = h[k].a;
                g_tx.destinations[2].is_subaddress = h[k].sub;
                g_tx.destinations[2].amount = 0;
                g_tx.n_destinations = 3;
                break;
            }
            expect_refused(h[k].reason);
        }
    }
}

MW_TEST(test_own_flag_lies)
{
    mw_tx_summary_t sum;
    // Own main address flagged as a subaddress: the output would be invisible.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].addr = g_tx.destinations[1].addr;
    g_tx.destinations[0].is_subaddress = true;
    g_tx.has_change_addr = false;
    g_tx.change_amount = 0;
    expect_refused(MW_TXR_OWN_FLAG);

    // Own (2,0) flagged as a standard address.
    build_account_tx(2, 3, 7);
    g_tx.destinations[0].addr = g_tx.destinations[1].addr;
    g_tx.destinations[0].is_subaddress = false;
    g_tx.has_change_addr = false;
    expect_refused(MW_TXR_OWN_FLAG);

    // The honest flag: an own recipient, marked as such.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].addr = g_tx.destinations[1].addr;
    g_tx.has_change_addr = false;
    g_tx.change_amount = 0;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK_EQ_INT(sum.n_recipients, 2);
    CHECK(sum.recipient_own[0] && sum.recipient_own[1]);
    CHECK_EQ_INT((int)sum.recipient_major[0], 0);
    CHECK(!sum.has_change);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
}

// Own subaddresses the device has not met yet are found by the bounded
// search; file hints alone never make an address own.
MW_TEST(test_own_subaddress_window)
{
    mw_tx_summary_t sum;
    mw_address_t a;

    // (0,4): inside the window.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 4, &a), MW_OK);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.recipient_own[0]);
    CHECK_EQ_INT((int)sum.recipient_minor[0], 4);
    CHECK(g_tx.check.searched > 0);
    CHECK_EQ_INT(sum.recipients[0][0], '8');
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);

    // (1,0): the next account's primary.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 1, 0, &a), MW_OK);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.recipient_own[0]);
    CHECK_EQ_INT((int)sum.recipient_major[0], 1);

    // X1: (0,1000000) named by a subaddr_indices hint only - refused.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 1000000, &a), MW_OK);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    g_tx.subaddr_hints[0] = 1000000;
    g_tx.n_subaddr_hints = 1;
    expect_refused(MW_TXR_HYBRID_VIEW_LINKED);
    CHECK(g_tx.check.searched > 0 && g_tx.check.searched <= MW_OWN_SEARCH_MAX);

    // X5: (0,250) is outside the default window ...
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 250, &a), MW_OK);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    expect_refused(MW_TXR_HYBRID_VIEW_LINKED);
    // ... and inside it once the device knows minor 60 of account 0.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    g_tx.own_max_minor_acct = 60;
    g_tx.own_max_minor_main = 60;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK_EQ_INT((int)sum.recipient_minor[0], 250);

    // X4: own 5/17 (another account, not its primary): refused unless the
    // key image cache knows it.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 5, 17, &a), MW_OK);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    expect_refused(MW_TXR_HYBRID_VIEW_LINKED);
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    g_tx.own_hint_major[0] = 5;
    g_tx.own_hint_minor[0] = 17;
    g_tx.n_own_hints = 1;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.recipient_own[0]);
    CHECK_EQ_INT((int)sum.recipient_major[0], 5);
    CHECK_EQ_INT((int)sum.recipient_minor[0], 17);

    // X3: spend key of own 0/150 with a foreign view key: refused once the
    // device knows 0/150 (outside that knowledge it is a residual risk).
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 150, &a), MW_OK);
    random_point(&a.view);
    g_tx.destinations[0].addr = a;
    g_tx.destinations[0].is_subaddress = true;
    g_tx.own_hint_major[0] = 0;
    g_tx.own_hint_minor[0] = 150;
    g_tx.n_own_hints = 1;
    expect_refused(MW_TXR_HYBRID_OUR_SPEND);
}

MW_TEST(test_change_claims)
{
    mw_tx_summary_t sum;
    mw_tx_check_info_t ci;

    // Claimed change ten times what the change address gets.
    build_tx(&g_tx, &g_keys);
    g_tx.change_amount = CHANGE_AMOUNT * 10;
    expect_refused(MW_TXR_CHANGE_UNPAID);
    build_tx(&g_tx, &g_keys);
    g_tx.change_amount = CHANGE_AMOUNT * 10;
    match_inputs(&g_tx);
    CHECK_EQ_INT(mw_tx_check_destinations(&g_keys, &g_tx, &ci), MW_ERR_KEY_MISMATCH);
    CHECK_EQ_INT((long long)ci.claimed, (long long)(CHANGE_AMOUNT * 10));
    CHECK_EQ_INT((long long)ci.paid, (long long)CHANGE_AMOUNT);

    // C7: change_dts claims our main address, the money goes elsewhere.
    build_tx(&g_tx, &g_keys);
    random_point(&g_tx.destinations[1].addr.spend);
    random_point(&g_tx.destinations[1].addr.view);
    expect_refused(MW_TXR_CHANGE_UNPAID);

    // change_dts is a FOREIGN address paid with change_amount 0: not a dummy.
    build_tx(&g_tx, &g_keys);
    g_tx.change_addr = g_tx.destinations[0].addr;
    g_tx.change_amount = 0;
    expect_refused(MW_TXR_CHANGE_NOT_OURS);

    // A send to self plus change, both to the main address: the change is
    // what was claimed, the rest an own recipient.
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].addr = g_tx.destinations[1].addr;
    g_tx.change_amount = CHANGE_AMOUNT - 5;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK(sum.has_change);
    CHECK_EQ_INT((long long)sum.change, (long long)(CHANGE_AMOUNT - 5));
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK(sum.recipient_own[0]);
    CHECK_EQ_INT((long long)sum.amounts[0], (long long)(SEND_AMOUNT + 5));
    CHECK_EQ_INT((long long)sum.total_out, (long long)(SEND_AMOUNT + 5));
}

MW_TEST(test_change_index_policy)
{
    mw_address_t a;
    // Change to (0,3) - ours, named by the hints and even an input, but not
    // where wallet2 sends change.
    build_tx(&g_tx, &g_keys);
    make_subaddress_source(&g_tx.sources[1], &g_keys, IN1_AMOUNT, 0, 3);
    g_tx.subaddr_hints[0] = 3;
    g_tx.n_subaddr_hints = 1;
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 3, &a), MW_OK);
    g_tx.destinations[1].addr = a;
    g_tx.destinations[1].is_subaddress = true;
    g_tx.change_addr = a;
    expect_refused(MW_TXR_CHANGE_INDEX);

    // subaddr_account 7 while the inputs are in account 0.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 7, 0, &a), MW_OK);
    g_tx.destinations[1].addr = a;
    g_tx.destinations[1].is_subaddress = true;
    g_tx.change_addr = a;
    g_tx.change_is_subaddress = true;
    g_tx.subaddr_account = 7;
    g_tx.sources[0].subaddr_known = true;     // matched as the review does
    g_tx.sources[1].subaddr_known = true;
    {
        static mw_transaction_t copy;
        copy = g_tx;
        mw_tx_check_info_t ci;
        CHECK_EQ_INT(mw_tx_check_destinations(&g_keys, &g_tx, &ci), MW_ERR_KEY_MISMATCH);
        CHECK_EQ_INT(ci.reason, MW_TXR_ACCOUNT);
        CHECK(mw_sign_transaction(&g_keys, &copy, &g_sd, NULL, NULL) != MW_OK);
    }

    // Inputs from two accounts in one transaction (wallet2 never does it).
    build_tx(&g_tx, &g_keys);
    make_subaddress_source(&g_tx.sources[1], &g_keys, IN1_AMOUNT, 1, 3);
    g_tx.sources[1].subaddr_known = true;
    g_tx.sources[1].subaddr_major = 1;
    g_tx.sources[1].subaddr_minor = 3;
    expect_refused(MW_TXR_ACCOUNT);

    // change_dts flag inconsistent with the account.
    build_tx(&g_tx, &g_keys);
    g_tx.change_is_subaddress = true;
    expect_refused(MW_TXR_CHANGE_FLAG);
    build_account_tx(2, 3, 7);
    g_tx.change_is_subaddress = false;
    expect_refused(MW_TXR_CHANGE_FLAG);
}

// wallet2's zero change: a 0-amount output to a random address.
MW_TEST(test_dummy_change)
{
    mw_tx_summary_t sum;
    build_tx(&g_tx, &g_keys);
    random_point(&g_tx.destinations[1].addr.spend);
    random_point(&g_tx.destinations[1].addr.view);
    g_tx.destinations[1].amount = 0;
    g_tx.change_addr = g_tx.destinations[1].addr;
    g_tx.change_amount = 0;
    g_tx.fee += CHANGE_AMOUNT;
    g_tx.destinations[0].amount = SEND_AMOUNT;
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK_EQ_INT(sum.n_dummy, 1);
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK(!sum.has_change);
    CHECK_EQ_INT((long long)sum.total_out, (long long)SEND_AMOUNT);
    CHECK_EQ_INT(g_tx.destinations[1].kind, MW_DEST_DUMMY);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    // The dummy output uses a*R, as wallet2's device_default does.
    mw_point_t der;
    mw_pubkey_t expect;
    CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.tx_public_key, &g_keys.sec.view, &der),
                 MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&der, 1, &g_tx.destinations[1].addr.spend, &expect),
                 MW_OK);
    CHECK_EQ_MEM(expect.b, g_tx.outputs[1].out_pubkey.b, 32);
    CHECK(!g_tx.out_ki_valid[1]);
}

// The change output is built from change_derived, the device's own keys.
MW_TEST(test_change_output_uses_derived_keys)
{
    build_account_tx(3, 1, 2);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    mw_address_t want;
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 3, 0, &want), MW_OK);
    CHECK_EQ_MEM(g_tx.change_derived.spend.b, want.spend.b, 32);
    CHECK_EQ_MEM(g_tx.change_derived.view.b, want.view.b, 32);
    mw_point_t der;
    mw_pubkey_t expect;
    CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.tx_public_key, &g_keys.sec.view, &der),
                 MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&der, 1, &want.spend, &expect), MW_OK);
    CHECK_EQ_MEM(expect.b, g_tx.outputs[1].out_pubkey.b, 32);
}

// D-int: an integrated recipient must be shown as its 106-character integrated
// address, not as the 95-character base address the same keys also produce.
//
// The unsigned tx set flags the destination as integrated but keeps the short
// payment id in tx_extra, so the summary has to go and fetch it. Re-deriving
// the address type from has_payment_id alone silently downgraded every
// integrated payment - and the user is instructed to compare the address on
// screen with the online wallet character by character, a comparison that then
// could not succeed for any integrated payment.
MW_TEST(test_summary_integrated_recipient)
{
    static const uint8_t pid[8] = { 0xde, 0xad, 0xbe, 0xef,
                                    0x01, 0x23, 0x45, 0x67 };
    mw_tx_summary_t sum;
    char integrated[MW_ADDRESS_STR_MAX], base[MW_ADDRESS_STR_MAX];

    build_tx(&g_tx, &g_keys);

    // What mw_parse_unsigned_tx() produces: the type flag is set, the payment
    // id is not in the destination record.
    g_tx.destinations[0].addr.type           = MW_ADDR_INTEGRATED;
    g_tx.destinations[0].addr.has_payment_id = false;
    memset(g_tx.destinations[0].addr.payment_id, 0, 8);

    // extra as wallet2 hands it over: a 9-byte nonce holding the id, then
    // the transaction public key.
    {
        mw_writer_t w;
        mw_writer_init(&w, g_tx.extra_in, sizeof g_tx.extra_in);
        mw_write_u8(&w, 0x02);              // TX_EXTRA_NONCE
        mw_write_u8(&w, 9);
        mw_write_u8(&w, 0x01);              // short payment id
        mw_write_bytes(&w, pid, 8);
        mw_write_u8(&w, 0x01);              // TX_EXTRA_TAG_PUBKEY
        mw_write_point(&w, &g_tx.destinations[0].addr.spend);   // any point
        CHECK(!w.overflow);
        g_tx.extra_in_len = (uint16_t)w.pos;
    }

    // The helper finds it ...
    {
        uint8_t got[8];
        CHECK(mw_tx_extra_find_payment_id(g_tx.extra_in, g_tx.extra_in_len, got));
        CHECK_EQ_MEM(got, pid, 8);
    }

    // ... and the summary shows the integrated address.
    CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK_EQ_INT((int)strlen(sum.recipients[0]), 106);
    CHECK_EQ_INT(sum.recipients[0][0], '4');

    {
        mw_address_t a;
        memset(&a, 0, sizeof a);
        a.spend = g_tx.destinations[0].addr.spend;
        a.view  = g_tx.destinations[0].addr.view;
        a.network = MW_NET_MAINNET;
        a.type = MW_ADDR_INTEGRATED;
        a.has_payment_id = true;
        memcpy(a.payment_id, pid, 8);
        CHECK_EQ_INT(mw_address_encode(&a, integrated, sizeof integrated), MW_OK);
        CHECK_EQ_STR(sum.recipients[0], integrated);

        a.type = MW_ADDR_STANDARD;
        a.has_payment_id = false;
        CHECK_EQ_INT(mw_address_encode(&a, base, sizeof base), MW_OK);
        CHECK_EQ_INT((int)strlen(base), 95);
        CHECK(strcmp(sum.recipients[0], base) != 0);
    }

    // The decoded integrated address must round-trip back to the same id.
    {
        mw_address_t back;
        CHECK_EQ_INT(mw_address_decode(integrated, &back), MW_OK);
        CHECK_EQ_INT(back.type, MW_ADDR_INTEGRATED);
        CHECK(back.has_payment_id);
        CHECK_EQ_MEM(back.payment_id, pid, 8);
    }

    // A destination flagged integrated with no payment id anywhere is a
    // corrupt file: refuse rather than quietly display the base address.
    g_tx.extra_in_len = 0;
    memset(g_tx.extra_in, 0, sizeof g_tx.extra_in);
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_ERR_FORMAT);

    // A subaddress destination is never integrated, whatever the type says.
    g_tx.destinations[0].is_subaddress = true;
    CHECK_EQ_INT(mw_tx_summarize(&g_tx, MW_NET_MAINNET, &sum), MW_OK);
    CHECK_EQ_INT(sum.recipients[0][0], '8');
}

// ------------------------------------------- construct_tx conformance
// An input received on subaddress (major, minor) through an additional key,
// as wallet2 sends to a subaddress next to other destinations.
static void make_subaddress_source(mw_tx_source_t* s, const mw_account_keys_t* keys,
                                   uint64_t amount, uint32_t major, uint32_t minor)
{
    make_source(s, keys, amount, 7, 2);
    mw_address_t a;
    CHECK_EQ_INT(mw_get_subaddress(keys, major, minor, &a), MW_OK);
    mw_scalar_t r;
    mw_sc_random(&r);
    CHECK_EQ_INT(mw_point_scalarmult(&s->real_out_additional_key, &r, &a.spend), 0);
    s->has_additional_key = true;
    random_point(&s->real_out_tx_key);               // someone else's main key
    mw_point_t derivation;
    CHECK_EQ_INT(mw_generate_key_derivation(&a.view, &r, &derivation), MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&derivation, 2, &a.spend,
                                      &s->ring[s->real_output_index].dest), MW_OK);
}

MW_TEST(test_sign_subaddress_input_needs_hint)
{
    build_tx(&g_tx, &g_keys);
    make_subaddress_source(&g_tx.sources[1], &g_keys, IN1_AMOUNT, 1, 3);

    // Without the wallet2 hints the device cannot find the subaddress.
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);

    // Both inputs in account 1 (wallet2 spends one account per tx), change
    // to (1,0).
    build_account_tx(1, 9, 3);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    bool found = false;
    for (uint8_t i = 0; i < g_tx.n_inputs; ++i) {
        if (g_tx.sources[i].subaddr_major == 1 && g_tx.sources[i].subaddr_minor == 3)
            found = true;
        CHECK_EQ_INT(mw_clsag_verify(g_sd.message, g_tx.sources[i].ring,
                                     g_tx.sources[i].ring_size, &g_sd.pseudo_outs[i],
                                     &g_tx.sources[i].key_image, &g_sd.clsag[i]), MW_OK);
    }
    CHECK(found);

    // A key image cache hint works just as well.
    build_account_tx(4, 2, 5);
    g_tx.n_subaddr_hints = 0;
    for (int i = 0; i < 2; ++i) {
        g_tx.sources[i].subaddr_known = true;
        g_tx.sources[i].subaddr_major = 4;
        g_tx.sources[i].subaddr_minor = i ? 5 : 2;
    }
    mw_keyimage_t ki;
    CHECK_EQ_INT(mw_sign_input_key_image(&g_keys, &g_tx, 1, &ki), MW_OK);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
}

// "Необходима проверка на подмену адреса для сдачи": the online wallet knows
// the view key, so it can forge a "subaddress" (S', a*S') whose spend key it
// owns. The signer must recompute the SPEND key, not just check the view key.
MW_TEST(test_sign_change_substitution)
{
    // Forged: view key consistent with our view secret, spend key foreign.
    build_tx(&g_tx, &g_keys);
    {
        mw_address_t forged;
        memset(&forged, 0, sizeof forged);
        random_point(&forged.spend);
        CHECK_EQ_INT(mw_point_scalarmult(&forged.view, &g_keys.sec.view, &forged.spend), 0);
        forged.type = MW_ADDR_SUBADDRESS;
        g_tx.destinations[1].addr = forged;
        g_tx.destinations[1].is_subaddress = true;
        g_tx.change_addr = forged;
    }
    expect_refused(MW_TXR_HYBRID_VIEW_LINKED);

    // Genuine change to the account's first subaddress (account 2).
    build_account_tx(2, 3, 9);
    match_inputs(&g_tx);
    CHECK_EQ_INT(mw_tx_check_destinations(&g_keys, &g_tx, NULL), MW_OK);
    CHECK(g_tx.change_verified);
    CHECK_EQ_INT(g_tx.change_major, 2);
    CHECK(g_tx.destinations[1].is_change);
    CHECK(!g_tx.destinations[0].is_change);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);

    // Its key image went into out_ki, and it is right: x = Hs(8aR||i) + b + m.
    CHECK(g_tx.out_ki_valid[1]);
    CHECK(!g_tx.out_ki_valid[0]);
    {
        mw_pubkey_t R = g_tx.tx_public_key;
        mw_seckey_t x;
        CHECK_EQ_INT(mw_output_secret(&g_keys, &g_tx.outputs[1].out_pubkey, &R, NULL,
                                      1, 2, 0, &x), MW_OK);
        mw_keyimage_t ki;
        CHECK_EQ_INT(mw_generate_key_image(&g_tx.outputs[1].out_pubkey, &x, &ki), MW_OK);
        CHECK_EQ_MEM(ki.b, g_tx.out_ki[1].b, 32);
    }

    // A destination that is not the change address is a recipient, shown to
    // the user, even when it happens to be our own address.
    build_tx(&g_tx, &g_keys);
    g_tx.has_change_addr = false;
    g_tx.change_amount = 0;
    {
        mw_tx_summary_t sum;
        CHECK_EQ_INT(review_tx(&g_tx, &sum), MW_OK);
        CHECK_EQ_INT(sum.n_recipients, 2);
        CHECK_EQ_INT((long long)sum.change, 0LL);
        CHECK(!sum.has_change);
        CHECK(!sum.recipient_own[0]);
        CHECK(sum.recipient_own[1]);
        CHECK_EQ_INT((int)sum.recipient_major[1], 0);
        CHECK_EQ_INT((int)sum.recipient_minor[1], 0);
    }
}

// sort_tx_extra() order and the payment id rules of construct_tx.
MW_TEST(test_sign_extra_layout)
{
    // No payment id, two destinations: a dummy encrypted id is added.
    build_tx(&g_tx, &g_keys);
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    CHECK_EQ_INT(g_tx.tx_extra_len, 33 + 11);
    CHECK_EQ_INT(g_tx.tx_extra[0], 0x01);
    CHECK_EQ_MEM(g_tx.tx_extra + 1, g_tx.tx_public_key.b, 32);
    CHECK_EQ_INT(g_tx.tx_extra[33], 0x02);
    CHECK_EQ_INT(g_tx.tx_extra[34], 9);
    CHECK_EQ_INT(g_tx.tx_extra[35], 0x01);
    {
        // It decrypts to zeros with the recipient's view key: 8*r*A.
        mw_point_t d;
        uint8_t buf[33], h[32];
        CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.destinations[0].addr.view,
                                                &g_tx.tx_secret_key, &d), MW_OK);
        memcpy(buf, d.b, 32);
        buf[32] = 0x8d;
        mw_keccak256(buf, 33, h);
        CHECK_EQ_MEM(g_tx.tx_extra + 36, h, 8);          // 0 ^ h == h
    }

    // A real payment id is encrypted for the single recipient.
    static const uint8_t pid[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    build_tx(&g_tx, &g_keys);
    g_tx.extra_in[0] = 0x02; g_tx.extra_in[1] = 9; g_tx.extra_in[2] = 0x01;
    memcpy(g_tx.extra_in + 3, pid, 8);
    g_tx.extra_in_len = 11;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    CHECK_EQ_INT(g_tx.tx_extra_len, 44);
    {
        mw_point_t d;
        uint8_t buf[33], h[32], dec[8];
        CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.destinations[0].addr.view,
                                                &g_tx.tx_secret_key, &d), MW_OK);
        memcpy(buf, d.b, 32);
        buf[32] = 0x8d;
        mw_keccak256(buf, 33, h);
        for (int i = 0; i < 8; ++i) dec[i] = g_tx.tx_extra[36 + i] ^ h[i];
        CHECK_EQ_MEM(dec, pid, 8);
    }

    // Three destinations and no payment id: no nonce at all.
    build_tx(&g_tx, &g_keys);
    {
        mw_scalar_t b, a;
        mw_sc_random(&b);
        mw_sc_random(&a);
        g_tx.destinations[2] = g_tx.destinations[0];
        mw_point_scalarmult_base(&g_tx.destinations[2].addr.spend, &b);
        mw_point_scalarmult_base(&g_tx.destinations[2].addr.view, &a);
        g_tx.destinations[2].amount = 1000;
        g_tx.destinations[1].amount -= 1000;
        g_tx.change_amount -= 1000;
        g_tx.n_destinations = 3;
    }
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    CHECK_EQ_INT(g_tx.tx_extra_len, 33);

    // A single subaddress recipient (change does not count): R = r*D and no
    // additional keys (classify_addresses: 0 standard, 1 subaddress).
    build_tx(&g_tx, &g_keys);
    g_tx.destinations[0].is_subaddress = true;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    {
        mw_point_t rD;
        CHECK_EQ_INT(mw_point_scalarmult(&rD, &g_tx.tx_secret_key,
                                         &g_tx.destinations[0].addr.spend), 0);
        CHECK_EQ_MEM(rD.b, g_tx.tx_public_key.b, 32);
        CHECK_EQ_INT(g_tx.tx_extra[33], 0x02);       // straight to the nonce
    }

    // A subaddress next to a standard recipient: one additional key per output.
    build_tx(&g_tx, &g_keys);
    {
        mw_scalar_t b, a;
        mw_sc_random(&b);
        mw_sc_random(&a);
        g_tx.destinations[2] = g_tx.destinations[0];
        mw_point_scalarmult_base(&g_tx.destinations[2].addr.spend, &b);
        mw_point_scalarmult_base(&g_tx.destinations[2].addr.view, &a);
        g_tx.destinations[2].amount = 1000;
        g_tx.destinations[1].amount -= 1000;
        g_tx.change_amount -= 1000;
        g_tx.n_destinations = 3;
        g_tx.destinations[0].is_subaddress = true;
    }
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
    CHECK_EQ_INT(g_tx.tx_extra[33], 0x04);
    CHECK_EQ_INT(g_tx.tx_extra[34], 3);
    CHECK_EQ_INT(g_tx.tx_extra_len, 33 + 2 + 3 * 32);

    // An extra field construct_tx cannot sort is refused, not dropped.
    build_tx(&g_tx, &g_keys);
    g_tx.extra_in[0] = 0x03;                      // merge mining tag
    g_tx.extra_in_len = 1;
    CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL),
                 MW_ERR_NOT_SUPPORTED);
}

MW_TEST(test_sign_shuffles_outputs)
{
    int seen_swapped = 0;
    for (int round = 0; round < 24; ++round) {
        build_tx(&g_tx, &g_keys);
        g_tx.no_shuffle = false;
        CHECK_EQ_INT(mw_sign_transaction(&g_keys, &g_tx, &g_sd, NULL, NULL), MW_OK);
        // out_dest is a permutation and each output pays its destination.
        CHECK(g_tx.out_dest[0] != g_tx.out_dest[1]);
        for (uint8_t i = 0; i < g_tx.n_outputs; ++i) {
            const mw_tx_destination_t* d = &g_tx.destinations[g_tx.out_dest[i]];
            CHECK_EQ_INT((long long)g_tx.outputs[i].amount, (long long)d->amount);
            if (d->is_change) {
                CHECK(g_tx.out_ki_valid[i]);
                mw_point_t der;
                mw_pubkey_t expect;
                CHECK_EQ_INT(mw_generate_key_derivation(&g_tx.tx_public_key,
                                                        &g_keys.sec.view, &der), MW_OK);
                CHECK_EQ_INT(mw_derive_public_key(&der, i, &g_keys.pub.spend, &expect), MW_OK);
                CHECK_EQ_MEM(expect.b, g_tx.outputs[i].out_pubkey.b, 32);
            }
        }
        if (g_tx.out_dest[0] == 1) seen_swapped++;
        CHECK_EQ_INT(mw_bpp_verify(&g_sd.bpp), MW_OK);
    }
    CHECK(seen_swapped > 0 && seen_swapped < 24);
}

int main(void)
{
    mw_random_init();
    CHECK_EQ_INT(mw_bpp_init(), MW_OK);
    test_account(&g_keys);

    RUN_TEST(test_sign_two_inputs_two_outputs);
    RUN_TEST(test_sign_zero_fee_balances);
    RUN_TEST(test_sign_rejects_unbalanced_amounts);
    RUN_TEST(test_sign_rejects_low_order_ring_point);
    RUN_TEST(test_sign_rejects_foreign_real_output);
    RUN_TEST(test_sign_rejects_bad_arguments);
    RUN_TEST(test_sign_reports_every_stage);
    RUN_TEST(test_summary_totals);
    RUN_TEST(test_summary_integrated_recipient);
    RUN_TEST(test_change_shown_main);
    RUN_TEST(test_change_shown_subaccount);
    RUN_TEST(test_hybrid_destinations_refused);
    RUN_TEST(test_own_flag_lies);
    RUN_TEST(test_own_subaddress_window);
    RUN_TEST(test_change_claims);
    RUN_TEST(test_change_index_policy);
    RUN_TEST(test_dummy_change);
    RUN_TEST(test_change_output_uses_derived_keys);
    RUN_TEST(test_sign_subaddress_input_needs_hint);
    RUN_TEST(test_sign_change_substitution);
    RUN_TEST(test_sign_extra_layout);
    RUN_TEST(test_sign_shuffles_outputs);

    mw_bpp_free();
    return mw_test_summary();
}
