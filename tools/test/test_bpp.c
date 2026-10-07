// Bulletproofs+ prover/verifier round trips.
//
// The proof is a Fiat-Shamir transform, so a passing round trip means the
// verifier accepts exactly the transcript the prover produced. The interesting
// cases are the range edges (0, 1, 2^64-1), the padding cases (3 outputs pad to
// M = 4) and the negative cases where a single tampered byte must be rejected.
#include "test_framework.h"

#include "monero/bulletproof_plus.h"
#include "crypto/ed25519.h"
#include "crypto/random.h"

static void random_mask(mw_scalar_t* s)
{
    mw_sc_random(s);
}

static void commitments_for(const uint64_t* amounts, const mw_scalar_t* masks,
                            uint8_t n, mw_point_t* out)
{
    for (uint8_t i = 0; i < n; ++i) {
        mw_scalar_t a;
        mw_sc_0(&a);
        for (int k = 0; k < 8; ++k) {
            a.b[k] = (uint8_t)((amounts[i] >> (8 * k)) & 0xff);
        }
        mw_commit(&out[i], &masks[i], &a);
    }
}

static int prove_verify(const uint64_t* amounts, uint8_t n, mw_bpp_proof_t* proof)
{
    mw_scalar_t masks[MW_BPP_MAX_OUTPUTS];
    for (uint8_t i = 0; i < n; ++i) {
        random_mask(&masks[i]);
    }
    if (mw_bpp_prove(amounts, masks, n, proof) != MW_OK) {
        return 0;
    }
    if (mw_bpp_verify(proof) != MW_OK) {
        return 0;
    }
    // The commitments in the proof must open to the amounts we asked for.
    mw_point_t c[MW_BPP_MAX_OUTPUTS];
    commitments_for(amounts, masks, n, c);
    return mw_bpp_check_commitments(proof, c, n) == MW_OK;
}

MW_TEST(test_single_output)
{
    const uint64_t amounts[1] = { 1234567890123ULL };
    mw_bpp_proof_t p;
    CHECK(prove_verify(amounts, 1, &p));
    CHECK_EQ_INT(p.n_v, 1);
    CHECK_EQ_INT(p.n_lr, 6);          // MN = 64 -> 6 rounds
}

MW_TEST(test_range_edges)
{
    const uint64_t zero[1] = { 0 };
    const uint64_t one[1] = { 1 };
    const uint64_t max[1] = { UINT64_MAX };
    const uint64_t high_bit[1] = { 0x8000000000000000ULL };
    mw_bpp_proof_t p;
    CHECK(prove_verify(zero, 1, &p));
    CHECK(prove_verify(one, 1, &p));
    CHECK(prove_verify(max, 1, &p));
    CHECK(prove_verify(high_bit, 1, &p));
}

MW_TEST(test_two_outputs)
{
    const uint64_t amounts[2] = { 0, UINT64_MAX };
    mw_bpp_proof_t p;
    CHECK(prove_verify(amounts, 2, &p));
    CHECK_EQ_INT(p.n_v, 2);
    CHECK_EQ_INT(p.n_lr, 7);          // MN = 128
}

MW_TEST(test_padded_outputs)
{
    // 3 outputs pad to M = 4, exercising the zero-padded aggregation slots.
    const uint64_t amounts[3] = { 1, 2, 3 };
    mw_bpp_proof_t p;
    CHECK(prove_verify(amounts, 3, &p));
    CHECK_EQ_INT(p.n_lr, 8);          // MN = 256

    const uint64_t five[5] = { 1000, 0, UINT64_MAX, 42, 7 };
    CHECK(prove_verify(five, 5, &p));
    CHECK_EQ_INT(p.n_lr, 9);          // M = 8 -> MN = 512
}

MW_TEST(test_random_vectors)
{
    for (int iter = 0; iter < 6; ++iter) {
        uint8_t rnd[8];
        mw_random_bytes(rnd, sizeof(rnd));
        uint8_t n = (uint8_t)(1 + (rnd[0] % 4));
        uint64_t amounts[4];
        for (uint8_t i = 0; i < n; ++i) {
            uint64_t v = 0;
            mw_random_bytes(&v, sizeof(v));
            amounts[i] = v >> (rnd[1] % 40);      // spread over the range
        }
        mw_bpp_proof_t p;
        CHECK(prove_verify(amounts, n, &p));
    }
}

MW_TEST(test_tampering_is_rejected)
{
    const uint64_t amounts[2] = { 5, 500000 };
    mw_scalar_t masks[2];
    random_mask(&masks[0]);
    random_mask(&masks[1]);
    mw_bpp_proof_t good;
    CHECK_EQ_INT(mw_bpp_prove(amounts, masks, 2, &good), MW_OK);
    CHECK_EQ_INT(mw_bpp_verify(&good), MW_OK);

    mw_bpp_proof_t p = good;
    p.r1.b[0] ^= 1;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    p = good;
    p.s1.b[3] ^= 0x10;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    p = good;
    p.d1.b[31] ^= 1;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    p = good;
    p.A.b[0] ^= 1;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    p = good;
    p.L[2].b[7] ^= 2;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    p = good;
    p.R[0].b[9] ^= 4;
    CHECK(mw_bpp_verify(&p) != MW_OK);

    // A commitment that does not belong to the proof.
    p = good;
    p.V[1] = good.V[0];
    CHECK(mw_bpp_verify(&p) != MW_OK);

    // Wrong padding claim.
    p = good;
    p.n_lr = 8;
    CHECK(mw_bpp_verify(&p) != MW_OK);
    p = good;
    p.n_v = 0;
    CHECK(mw_bpp_verify(&p) != MW_OK);
}

MW_TEST(test_commitment_check)
{
    const uint64_t amounts[2] = { 7, 9 };
    mw_scalar_t masks[2];
    random_mask(&masks[0]);
    random_mask(&masks[1]);
    mw_bpp_proof_t p;
    CHECK_EQ_INT(mw_bpp_prove(amounts, masks, 2, &p), MW_OK);

    mw_point_t c[2];
    commitments_for(amounts, masks, 2, c);
    CHECK_EQ_INT(mw_bpp_check_commitments(&p, c, 2), MW_OK);

    c[0].b[0] ^= 1;
    CHECK(mw_bpp_check_commitments(&p, c, 2) != MW_OK);
}

MW_TEST(test_serialize_round_trip)
{
    const uint64_t amounts[1] = { 999 };
    mw_scalar_t mask;
    random_mask(&mask);
    mw_bpp_proof_t p;
    CHECK_EQ_INT(mw_bpp_prove(amounts, &mask, 1, &p), MW_OK);

    uint8_t buf[1024];
    size_t n = mw_bpp_serialize(&p, buf, sizeof(buf));
    CHECK(n > 0);
    // A || A1 || B || r1 || s1 || d1 || varint || 6*L || varint || 6*R
    CHECK_EQ_INT(n, 6 * 32 + 1 + 6 * 32 + 1 + 6 * 32);

    mw_bpp_proof_t q;
    CHECK_EQ_INT(mw_bpp_deserialize(buf, n, &q), MW_OK);
    CHECK_EQ_INT(q.n_lr, p.n_lr);
    CHECK_EQ_MEM(q.A.b, p.A.b, 32);
    CHECK_EQ_MEM(q.d1.b, p.d1.b, 32);
    CHECK_EQ_MEM(q.L[5].b, p.L[5].b, 32);
    CHECK_EQ_MEM(q.R[0].b, p.R[0].b, 32);

    // V is not on the wire; the caller restores it from outPk.
    CHECK_EQ_INT(q.n_v, 0);
    q.n_v = p.n_v;
    for (uint8_t i = 0; i < p.n_v; ++i) {
        q.V[i] = p.V[i];
    }
    CHECK_EQ_INT(mw_bpp_verify(&q), MW_OK);

    // Truncated / oversized inputs must be rejected, never read out of bounds.
    mw_bpp_proof_t r;
    CHECK(mw_bpp_deserialize(buf, n - 1, &r) != MW_OK);
    CHECK(mw_bpp_deserialize(buf, 0, &r) != MW_OK);
    uint8_t bad[1024];
    memcpy(bad, buf, n);
    bad[6 * 32] = 11;                              // log2(MN) out of range
    CHECK(mw_bpp_deserialize(bad, n, &r) != MW_OK);
    bad[6 * 32] = 5;                               // below the minimum
    CHECK(mw_bpp_deserialize(bad, n, &r) != MW_OK);
}

MW_TEST(test_bad_arguments)
{
    const uint64_t amounts[1] = { 1 };
    mw_scalar_t mask;
    random_mask(&mask);
    mw_bpp_proof_t p;
    CHECK_EQ_INT(mw_bpp_prove(amounts, &mask, 0, &p), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_bpp_prove(amounts, &mask, MW_BPP_MAX_OUTPUTS + 1, &p),
                 MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_bpp_prove(NULL, &mask, 1, &p), MW_ERR_INVALID_ARG);
}

// Real mainnet vector: tx b80b07e27cae1de8455f553d5a2ac4e8826f9a7f2ea5e8bd8054763a97ca29f4
// (block 3775136, 2 outputs), accepted by the network. V = outPk * INV_EIGHT,
// as in rctSigs verRctSemanticsSimple. Guards consensus compatibility of the
// generators, the transcript (seed = hash_to_p3(cn_fast_hash(domain))) and
// the verifier equation - a self-consistent but non-Monero BP+ fails here.
static const char REAL_BPP[] =
    "5e2f61cd0e46c1ed19f1a1465d8a1e9ab18d05ea8f2c957c4a131ce2d5eaf118"
    "d8340f7d9a54f1f7c81cc069c04b596619fcb7e2ec1548534a1379c3115e340e"
    "68d9f99a9738c5483f9ea8f7fa98f6d0d7cc4b51294c868545878d1762fdcac2"
    "91abb15c44f4e638d069a8c9f4aaa0b3d1544119d9aedfab0b2de5e871126e0e"
    "3d255c04b64f6561e1300d1dedcbe2b74a71877dc3864c72abc990994fddcc05"
    "5ea8c66037c1bdfd8d91f4a35a038da9469ebffc201e36518de1584d9e7b0d0d"
    "07f08cdc55d7e2c311690093d0b60bd3a1b4c901a3790ccf06766e131fde6705"
    "24babe7cadeaa4910291d11717127a6e653bcfa68361b7b8cf9347930da0b987"
    "0bbe4b2c905064ff2e65dea66489e100d5dfd2112b700e3d1d4b593770f9691f"
    "02ccc2e2d25c09bfc5a463670bab828a56ea8b82ca8fd14be97fc63e9367d8f9"
    "11613ff0699f6adddbe9f48f074769c83a7718af8779bd2ef267f1daefc6ecec"
    "9f37758ac8cb53d935db51f6df04ec36c7f4114a88062de90d874718ea10e55e"
    "e62431779510b82bc96a2bfade33bcd8f79a99456173abd2f5f3e3ab6abb2514"
    "0f07cdf5755923900b7ce34926c8dea09dbd64e03cc5f24bda307e8203a628c5"
    "d24f5e4b94bf31412a9c715c56a9cdd2e7bf1a5c48799d65a5336bae06b0c26b"
    "c16057411c80240841072ca04878a1f7684209bc1ce18cb82bb5ee1af10e4525"
    "1f82b214492e337daf372e6be0b9c0dd6c0d3185f0777fe187a7cac905d9e8d1"
    "3fc5279d383ea1b59e27066c10256cd56ff8ebb90a4a37992a46b56b860f2626"
    "e996860ce1af1af8eafe16c30e5e3d0bd8091746b03d6e892b949e8a3161329e"
    "cdf0040533dc836e03861aa3cac94038acf0cb2d338c680272baac27454d6103"
    "6be6"
;
static const char REAL_OUTPK[] =
    "fcbc49fe3bf3044b0971ab878b136f95a019597a6d5649f5fd8480a0b3962b04"
    "555efb805d879a10e9369a610a45c7709f6fbbbf0ae59f90c0ed0abbec9786c9"
;

MW_TEST(test_real_mainnet_proof)
{
    uint8_t blob[1024];
    size_t len = mw_test_hex(REAL_BPP, blob, sizeof(blob));
    mw_bpp_proof_t p;
    CHECK_EQ_INT(mw_bpp_deserialize(blob, len, &p), MW_OK);
    CHECK_EQ_INT(p.n_lr, 7);

    mw_point_t outpk[2];
    CHECK_EQ_INT((int)mw_test_hex(REAL_OUTPK, outpk[0].b, sizeof(outpk)), 64);
    mw_scalar_t eight, inv8;
    mw_sc_0(&eight);
    eight.b[0] = 8;
    mw_sc_invert(&inv8, &eight);
    for (int i = 0; i < 2; ++i) {
        CHECK_EQ_INT(mw_point_scalarmult(&p.V[i], &inv8, &outpk[i]), 0);
    }
    p.n_v = 2;
    CHECK_EQ_INT(mw_bpp_verify(&p), MW_OK);
    CHECK_EQ_INT(mw_bpp_check_commitments(&p, outpk, 2), MW_OK);

    // Re-serialization is byte exact, and a flipped bit is rejected.
    uint8_t again[1024];
    CHECK_EQ_INT((int)mw_bpp_serialize(&p, again, sizeof(again)), (int)len);
    CHECK(memcmp(again, blob, len) == 0);
    p.r1.b[0] ^= 1;
    CHECK(mw_bpp_verify(&p) != MW_OK);
}

int main(void)
{
    mw_random_init();
    CHECK_EQ_INT(mw_bpp_init(), MW_OK);

    RUN_TEST(test_single_output);
    RUN_TEST(test_range_edges);
    RUN_TEST(test_two_outputs);
    RUN_TEST(test_padded_outputs);
    RUN_TEST(test_random_vectors);
    RUN_TEST(test_tampering_is_rejected);
    RUN_TEST(test_commitment_check);
    RUN_TEST(test_serialize_round_trip);
    RUN_TEST(test_bad_arguments);
    RUN_TEST(test_real_mainnet_proof);

    mw_bpp_free();
    return mw_test_summary();
}
