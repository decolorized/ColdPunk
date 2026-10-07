// Bulletproofs+ range proofs (TZ 12, RCT type 6).
//
// Memory note: a 2-output proof needs 2*64 = 128 generators per side. On
// ESP32-S3 the generator tables and the working vectors are allocated from
// PSRAM; see mw_bpp_set_allocator().
#ifndef MW_BULLETPROOF_PLUS_H
#define MW_BULLETPROOF_PLUS_H

#include "monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_BPP_MAX_OUTPUTS 16
#define MW_BPP_MAX_M       16          // padded output count (power of two)
#define MW_BPP_N           64          // bits per range
#define MW_BPP_MAX_MN      (MW_BPP_MAX_M * MW_BPP_N)
#define MW_BPP_MAX_LOG_MN  10          // log2(16*64)

typedef struct {
    mw_point_t  A, A1, B;
    mw_scalar_t r1, s1, d1;
    mw_point_t  L[MW_BPP_MAX_LOG_MN];
    mw_point_t  R[MW_BPP_MAX_LOG_MN];
    uint8_t     n_lr;                  // log2(M*N)
    mw_point_t  V[MW_BPP_MAX_OUTPUTS]; // commitments / 8, as serialized
    uint8_t     n_v;
} mw_bpp_proof_t;

// Proves that every `amounts[i]` is in [0, 2^64) under commitment
// C_i = masks[i]*G + amounts[i]*H.
mw_err_t mw_bpp_prove(const uint64_t* amounts, const mw_scalar_t* masks,
                      uint8_t n, mw_bpp_proof_t* proof_out);

// Verifies a proof. The device verifies its own output before signing
// (defence against fault injection).
mw_err_t mw_bpp_verify(const mw_bpp_proof_t* proof);

// TZ 8.3: checks V[i] * 8 == outPk[i].mask for every output.
mw_err_t mw_bpp_check_commitments(const mw_bpp_proof_t* proof,
                                  const mw_point_t* out_commitments, uint8_t n);

size_t   mw_bpp_serialize(const mw_bpp_proof_t* p, uint8_t* out, size_t out_len);
mw_err_t mw_bpp_deserialize(const uint8_t* in, size_t len, mw_bpp_proof_t* out);

// Generator cache lives in PSRAM on the device. Call once at boot.
mw_err_t mw_bpp_init(void);
void     mw_bpp_free(void);

// Progress callback so the UI can drive the progress bar during the (slow)
// proof generation. `permille` is 0..1000.
typedef void (*mw_progress_cb)(int permille, void* user);
void mw_bpp_set_progress_cb(mw_progress_cb cb, void* user);

#ifdef __cplusplus
}
#endif
#endif
