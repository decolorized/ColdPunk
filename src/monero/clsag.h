// CLSAG ring signatures (TZ 12). Constant-time on the secret index.
#ifndef MW_CLSAG_H
#define MW_CLSAG_H

#include "monero_types.h"
#include "tx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mw_scalar_t   s[MW_MAX_RING_SIZE];
    uint8_t       n;           // ring size
    mw_scalar_t   c1;
    mw_point_t    D;           // commitment key image / 8
    mw_keyimage_t I;           // not serialized (taken from the input)
} mw_clsag_t;

// Signs one input.
//   message   : the RCT message hash
//   ring      : ring members (P_i, C_i)
//   n         : ring size
//   real_idx  : index of our member
//   p         : one-time secret key of the real member
//   z         : mask difference (real_mask - pseudo_out_mask)
//   C_offset  : pseudoOut commitment
mw_err_t mw_clsag_sign(const uint8_t message[32], const mw_ctkey_t* ring, uint8_t n,
                       uint8_t real_idx, const mw_seckey_t* p, const mw_scalar_t* z,
                       const mw_point_t* C_offset, const mw_keyimage_t* I,
                       mw_clsag_t* sig_out);

// Self-verification: the device always verifies what it just signed before
// writing it out.
mw_err_t mw_clsag_verify(const uint8_t message[32], const mw_ctkey_t* ring, uint8_t n,
                         const mw_point_t* C_offset, const mw_keyimage_t* I,
                         const mw_clsag_t* sig);

#ifdef __cplusplus
}
#endif
#endif
