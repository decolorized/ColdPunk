// Key images, the export ring signature and the outputs.bin -> keyimages.bin
// batch pipeline (TZ 11).
#include "test_framework.h"

#include "monero/file_formats.h"   // MW_MAX_EXPORTED_OUTPUTS (TZ 11.3 cap)
#include "monero/key_image.h"
#include "monero/keys.h"
#include "crypto/ed25519.h"
#include "crypto/random.h"

static void test_account(mw_account_keys_t* keys)
{
    uint8_t seed[32];
    mw_random_bytes(seed, sizeof(seed));
    mw_keys_from_legacy_seed(seed, keys);
    mw_keys_derive_public(keys);
}

// Builds an output that really was paid to `keys` at (major, minor):
// picks a tx key r, derives R (and the additional key for subaddresses) and
// the one-time public key P the sender would have written into the chain.
static void make_output(const mw_account_keys_t* keys, uint32_t index,
                        uint32_t major, uint32_t minor, bool use_additional,
                        mw_exported_output_t* out)
{
    memset(out, 0, sizeof(*out));
    out->internal_output_index = index;
    out->global_output_index = 1000 + index;
    out->subaddr_major = major;
    out->subaddr_minor = minor;
    out->amount = 12345;
    out->rct = true;

    mw_address_t addr;
    mw_get_subaddress(keys, major, minor, &addr);

    mw_seckey_t r;
    mw_sc_random(&r);

    mw_point_t derivation;
    if (use_additional) {
        // Subaddress output: R_i = r*B_i and the derivation uses that key.
        mw_point_scalarmult(&out->additional_tx_pub, &r, &addr.spend);
        out->has_additional = true;
        out->additional_count = index + 1;
        // The main tx key belongs to some other output of the same tx.
        mw_scalar_t other;
        mw_sc_random(&other);
        mw_point_scalarmult_base(&out->tx_pub_key, &other);
        mw_generate_key_derivation(&addr.view, &r, &derivation);
    } else if (major != 0 || minor != 0) {
        // Single-destination transfer to a SUBADDRESS. Monero does not put
        // r*G in tx_pub_key here - cryptonote_tx_utils.cpp sets R = r*D, the
        // subaddress spend public key:
        //     if (num_stdaddresses == 0 && num_subaddresses == 1)
        //         txkey_pub = scalarmultKey(single_dest.m_spend_public_key, r);
        // Only then does the receiver's 8*a*R equal the sender's 8*r*C,
        // because C = a*D. With r*G the two sides derive different shared
        // secrets and the one-time key never matches.
        mw_point_scalarmult(&out->tx_pub_key, &r, &addr.spend);
        mw_generate_key_derivation(&addr.view, &r, &derivation);
    } else {
        // Main address: the ordinary R = r*G.
        mw_point_scalarmult_base(&out->tx_pub_key, &r);
        mw_generate_key_derivation(&addr.view, &r, &derivation);
    }
    mw_derive_public_key(&derivation, index, &addr.spend, &out->one_time_pubkey);
}

MW_TEST(test_key_image_basics)
{
    mw_scalar_t x;
    mw_sc_random(&x);
    mw_point_t P;
    mw_point_scalarmult_base(&P, &x);

    mw_keyimage_t I1, I2;
    CHECK_EQ_INT(mw_generate_key_image(&P, &x, &I1), MW_OK);
    CHECK_EQ_INT(mw_generate_key_image(&P, &x, &I2), MW_OK);
    CHECK_EQ_MEM(I1.b, I2.b, 32);                // deterministic
    CHECK(mw_point_check_public(&I1));

    // I = x*Hp(P): recompute it the long way.
    mw_ge_p3 hp;
    mw_hash_to_ec(P.b, 32, &hp);
    mw_ge_p3 expect;
    mw_ge_scalarmult(&expect, &x, &hp);
    mw_point_t expect_bytes;
    mw_ge_p3_tobytes(&expect_bytes, &expect);
    CHECK_EQ_MEM(I1.b, expect_bytes.b, 32);

    // A different key gives a different image.
    mw_scalar_t y;
    mw_sc_random(&y);
    mw_point_t Q;
    mw_point_scalarmult_base(&Q, &y);
    mw_keyimage_t I3;
    CHECK_EQ_INT(mw_generate_key_image(&Q, &y, &I3), MW_OK);
    CHECK(memcmp(I1.b, I3.b, 32) != 0);

    // TZ 8.3: x*G must match P.
    CHECK_EQ_INT(mw_generate_key_image(&Q, &x, &I3), MW_ERR_KEY_MISMATCH);
    CHECK_EQ_INT(mw_generate_key_image(NULL, &x, &I3), MW_ERR_INVALID_ARG);
}

MW_TEST(test_export_signature)
{
    mw_scalar_t x;
    mw_sc_random(&x);
    mw_point_t P;
    mw_point_scalarmult_base(&P, &x);
    mw_keyimage_t I;
    CHECK_EQ_INT(mw_generate_key_image(&P, &x, &I), MW_OK);

    mw_ring_sig_t sig;
    CHECK_EQ_INT(mw_generate_key_image_signature(&P, &x, &I, &sig), MW_OK);
    CHECK_EQ_INT(mw_check_key_image_signature(&P, &I, &sig), MW_OK);
    CHECK(mw_sc_check(&sig.c));
    CHECK(mw_sc_check(&sig.r));

    // Every field is covered by the challenge.
    mw_ring_sig_t bad = sig;
    bad.c.b[0] ^= 1;
    CHECK(mw_check_key_image_signature(&P, &I, &bad) != MW_OK);
    bad = sig;
    bad.r.b[9] ^= 8;
    CHECK(mw_check_key_image_signature(&P, &I, &bad) != MW_OK);

    mw_keyimage_t other_image = I;
    other_image.b[0] ^= 1;
    CHECK(mw_check_key_image_signature(&P, &other_image, &sig) != MW_OK);

    mw_point_t other_pub = P;
    other_pub.b[0] ^= 1;
    CHECK(mw_check_key_image_signature(&other_pub, &I, &sig) != MW_OK);

    // Signing needs the matching secret.
    mw_scalar_t y;
    mw_sc_random(&y);
    CHECK_EQ_INT(mw_generate_key_image_signature(&P, &y, &I, &sig),
                 MW_ERR_KEY_MISMATCH);

    // A fresh nonce every time.
    mw_ring_sig_t sig2;
    CHECK_EQ_INT(mw_generate_key_image_signature(&P, &x, &I, &sig2), MW_OK);
    CHECK(memcmp(sig.c.b, sig2.c.b, 32) != 0);
    CHECK_EQ_INT(mw_check_key_image_signature(&P, &I, &sig2), MW_OK);
}

MW_TEST(test_from_output_main_address)
{
    mw_account_keys_t keys;
    test_account(&keys);

    for (uint32_t idx = 0; idx < 3; ++idx) {
        mw_exported_output_t out;
        make_output(&keys, idx, 0, 0, false, &out);

        mw_exported_key_image_t ki;
        CHECK_EQ_INT(mw_key_image_from_output(&keys, &out, &ki), MW_OK);
        CHECK_EQ_INT(mw_check_key_image_signature(&out.one_time_pubkey, &ki.image,
                                                  &ki.sig), MW_OK);
        CHECK(mw_point_check_public(&ki.image));
    }
}

MW_TEST(test_from_output_subaddress)
{
    mw_account_keys_t keys;
    test_account(&keys);

    // Subaddress output carried by an additional tx public key.
    mw_exported_output_t out;
    make_output(&keys, 2, 1, 7, true, &out);
    mw_exported_key_image_t ki;
    CHECK_EQ_INT(mw_key_image_from_output(&keys, &out, &ki), MW_OK);
    CHECK_EQ_INT(mw_check_key_image_signature(&out.one_time_pubkey, &ki.image,
                                              &ki.sig), MW_OK);

    // Same output but the record claims the wrong subaddress index.
    mw_exported_output_t wrong = out;
    wrong.subaddr_minor = 8;
    CHECK(mw_key_image_from_output(&keys, &wrong, &ki) != MW_OK);

    // A subaddress paid through the main tx key (single-destination case).
    mw_exported_output_t plain;
    make_output(&keys, 0, 2, 3, false, &plain);
    CHECK_EQ_INT(mw_key_image_from_output(&keys, &plain, &ki), MW_OK);
}

static void random_foreign(mw_pubkey_t* p)
{
    mw_scalar_t s;
    mw_sc_random(&s);
    mw_point_scalarmult_base(p, &s);
}

MW_TEST(test_from_output_rejects_junk)
{
    mw_account_keys_t keys;
    test_account(&keys);

    mw_exported_output_t out;
    make_output(&keys, 0, 0, 0, false, &out);
    mw_exported_key_image_t ki;

    // An output that is not ours.
    mw_exported_output_t foreign = out;
    mw_scalar_t s;
    mw_sc_random(&s);
    mw_point_scalarmult_base(&foreign.one_time_pubkey, &s);
    CHECK_EQ_INT(mw_key_image_from_output(&keys, &foreign, &ki),
                 MW_ERR_KEY_MISMATCH);

    // Points that do not decode / are off the main subgroup.
    mw_exported_output_t junk = out;
    memset(junk.tx_pub_key.b, 0xff, 32);
    CHECK(mw_key_image_from_output(&keys, &junk, &ki) != MW_OK);

    junk = out;
    memset(junk.one_time_pubkey.b, 0xff, 32);
    CHECK(mw_key_image_from_output(&keys, &junk, &ki) != MW_OK);

    // A junk additional key (not a curve point) must be refused, not used.
    junk = out;
    random_foreign(&junk.one_time_pubkey);
    junk.has_additional = true;
    memset(junk.additional_tx_pub.b, 0xff, 32);
    CHECK(mw_key_image_from_output(&keys, &junk, &ki) != MW_OK);

    // A view-only wallet cannot produce key images.
    mw_account_keys_t view_only = keys;
    view_only.view_only = true;
    CHECK_EQ_INT(mw_key_image_from_output(&view_only, &out, &ki),
                 MW_ERR_NOT_SUPPORTED);
}

static uint32_t g_progress_done;
static uint32_t g_progress_total;
static uint32_t g_progress_calls;

static void progress_cb(uint32_t done, uint32_t total, void* user)
{
    (void)user;
    g_progress_done = done;
    g_progress_total = total;
    ++g_progress_calls;
}

MW_TEST(test_batch_skips_bad_records)
{
    mw_account_keys_t keys;
    test_account(&keys);

    enum { N = 6 };
    mw_exported_output_t outs[N];
    for (uint32_t i = 0; i < N; ++i) {
        make_output(&keys, i, 0, 0, false, &outs[i]);
    }
    // Corrupt two records in the middle: one that is simply not ours, and one
    // whose one-time key is not even a curve point.
    mw_scalar_t s;
    mw_sc_random(&s);
    mw_point_scalarmult_base(&outs[2].one_time_pubkey, &s);
    memset(outs[3].tx_pub_key.b, 0xff, 32);

    mw_exported_key_image_t images[N];
    mw_ki_failure_t failures[2];
    mw_ki_batch_result_t result;
    memset(&result, 0, sizeof(result));
    result.failures = failures;
    result.failures_cap = 2;

    g_progress_calls = 0;
    CHECK_EQ_INT(mw_key_image_batch(&keys, outs, N, images, &result,
                                    progress_cb, NULL), MW_OK);
    CHECK_EQ_INT(result.processed, N - 2);
    CHECK_EQ_INT(result.failed, 2);
    CHECK_EQ_INT(failures[0].index, 2);
    CHECK_EQ_INT(failures[0].err, MW_ERR_KEY_MISMATCH);
    CHECK_EQ_INT(failures[1].index, 3);
    CHECK_EQ_INT(g_progress_calls, N);
    CHECK_EQ_INT(g_progress_done, N);
    CHECK_EQ_INT(g_progress_total, N);

    // The good records are untouched by their bad neighbours.
    for (uint32_t i = 0; i < N; ++i) {
        if (i == 2 || i == 3) {
            mw_keyimage_t zero;
            memset(zero.b, 0, 32);
            CHECK_EQ_MEM(images[i].image.b, zero.b, 32);
            continue;
        }
        mw_exported_key_image_t expect;
        CHECK_EQ_INT(mw_key_image_from_output(&keys, &outs[i], &expect), MW_OK);
        CHECK_EQ_MEM(images[i].image.b, expect.image.b, 32);
        CHECK_EQ_INT(mw_check_key_image_signature(&outs[i].one_time_pubkey,
                                                  &images[i].image,
                                                  &images[i].sig), MW_OK);
    }
}

MW_TEST(test_batch_edges)
{
    mw_account_keys_t keys;
    test_account(&keys);

    mw_exported_key_image_t images[4];
    mw_ki_batch_result_t result;
    memset(&result, 0, sizeof(result));

    // Empty batch.
    mw_exported_output_t outs[4];
    CHECK_EQ_INT(mw_key_image_batch(&keys, outs, 0, images, &result, NULL, NULL),
                 MW_OK);
    CHECK_EQ_INT(result.processed, 0);

    // Every record bad -> the last error is returned.
    for (uint32_t i = 0; i < 4; ++i) {
        make_output(&keys, i, 0, 0, false, &outs[i]);
        mw_scalar_t s;
        mw_sc_random(&s);
        mw_point_scalarmult_base(&outs[i].one_time_pubkey, &s);
    }
    memset(&result, 0, sizeof(result));
    CHECK_EQ_INT(mw_key_image_batch(&keys, outs, 4, images, &result, NULL, NULL),
                 MW_ERR_KEY_MISMATCH);
    CHECK_EQ_INT(result.failed, 4);
    CHECK_EQ_INT(result.processed, 0);

    // Failures past the cap are still counted.
    mw_ki_failure_t one[1];
    memset(&result, 0, sizeof(result));
    result.failures = one;
    result.failures_cap = 1;
    CHECK(mw_key_image_batch(&keys, outs, 4, images, &result, NULL, NULL) != MW_OK);
    CHECK_EQ_INT(result.failed, 4);
    CHECK_EQ_INT(one[0].index, 0);

    // The TZ 11.3 cap is enforced.
    CHECK_EQ_INT(mw_key_image_batch(&keys, outs, MW_MAX_EXPORTED_OUTPUTS + 1,
                                    images, &result, NULL, NULL),
                 MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_key_image_batch(&keys, NULL, 1, images, &result, NULL, NULL),
                 MW_ERR_INVALID_ARG);
}

int main(void)
{
    mw_random_init();

    RUN_TEST(test_key_image_basics);
    RUN_TEST(test_export_signature);
    RUN_TEST(test_from_output_main_address);
    RUN_TEST(test_from_output_subaddress);
    RUN_TEST(test_from_output_rejects_junk);
    RUN_TEST(test_batch_skips_bad_records);
    RUN_TEST(test_batch_edges);

    return mw_test_summary();
}
