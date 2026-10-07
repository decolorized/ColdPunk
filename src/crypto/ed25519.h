// Ed25519 group and scalar arithmetic in the form Monero needs it.
//
// This is the ref10 field/group model (fe / ge_p3 / ge_p2 / ge_p1p1 / ge_cached)
// plus the extra operations Monero adds on top: ge_fromfe_frombytes_vartime
// (hash_to_point), ge_double_scalarmult_precomp_vartime, subgroup checks, etc.
//
// Conventions used throughout the project:
//   * mw_scalar_t  - 32-byte little-endian scalar, always reduced mod l.
//   * mw_point_t   - 32-byte compressed Edwards point.
//   * "_vartime"   - variable time, only ever used on PUBLIC data.
#ifndef MW_ED25519_H
#define MW_ED25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint8_t b[32]; } mw_scalar_t;   // little-endian, < l
typedef struct { uint8_t b[32]; } mw_point_t;    // compressed Edwards

// Field element, ref10 representation (10 limbs, 25.5-bit radix).
typedef int32_t mw_fe[10];

typedef struct { mw_fe X, Y, Z, T; } mw_ge_p3;
typedef struct { mw_fe X, Y, Z;    } mw_ge_p2;
typedef struct { mw_fe X, Y, Z, T; } mw_ge_p1p1;
typedef struct { mw_fe YplusX, YminusX, Z, T2d; } mw_ge_cached;
typedef struct { mw_fe yplusx, yminusx, xy2d;   } mw_ge_precomp;

// ---------------- constants ----------------------------------------------
extern const mw_scalar_t MW_SC_ZERO;
extern const mw_scalar_t MW_SC_ONE;
extern const mw_scalar_t MW_SC_L;        // group order l (not reduced!)
extern const mw_point_t  MW_POINT_G;     // Ed25519 base point
// Monero's second generator H. It is a HARD-CODED CONSTANT
// (8b655970...d39c1f94), not a derived value: Monero's own source comment
// says "H = toPoint(cn_fast_hash(G))", but recomputing that yields
// d6329b5b...51a6498a instead. The comment is historically inaccurate and the
// real constant comes from rctTypes.h. Do not "fix" this by re-deriving it -
// a wrong H silently breaks every Pedersen commitment.
extern const mw_point_t  MW_POINT_H;
extern const mw_point_t  MW_POINT_IDENTITY;
extern const mw_ge_p3    MW_GE_P3_H;     // H in expanded form

// ---------------- scalar arithmetic (mod l) -------------------------------
void mw_sc_reduce32(mw_scalar_t* s);                       // in place, 32 bytes
void mw_sc_reduce64(mw_scalar_t* out, const uint8_t in[64]);
void mw_sc_add(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b);
void mw_sc_sub(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b);
// Bit-exact port of Monero's crypto-ops.c sc_sub(), including its handling of
// NON-reduced 256-bit inputs. cryptonote::decrypt_key() (the "seed offset"
// passphrase of Monero CLI / GUI / Feather) subtracts a raw cn_slow_hash from
// a raw 32-byte seed with it, so the plain mw_sc_sub(), which assumes reduced
// operands, would derive a different wallet. Output is 32 bytes, not
// necessarily < l; callers reduce afterwards exactly like Monero does.
void mw_sc_sub_ref10(uint8_t s[32], const uint8_t a[32], const uint8_t b[32]);
void mw_sc_mul(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b);
// r = (a*b + c) mod l
void mw_sc_muladd(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b,
                  const mw_scalar_t* c);
// r = (c - a*b) mod l  (Monero's sc_mulsub)
void mw_sc_mulsub(mw_scalar_t* r, const mw_scalar_t* a, const mw_scalar_t* b,
                  const mw_scalar_t* c);
void mw_sc_invert(mw_scalar_t* r, const mw_scalar_t* a);   // a^(l-2) mod l
int  mw_sc_is_zero(const mw_scalar_t* s);
int  mw_sc_check(const mw_scalar_t* s);   // 1 if canonical (s < l)
int  mw_sc_eq(const mw_scalar_t* a, const mw_scalar_t* b);
void mw_sc_0(mw_scalar_t* s);
void mw_sc_1(mw_scalar_t* s);
void mw_sc_random(mw_scalar_t* s);        // uniform in [1, l-1], uses mw_random

// hash_to_scalar: sc_reduce32(keccak256(data))
void mw_hash_to_scalar(const uint8_t* data, size_t len, mw_scalar_t* out);

// ---------------- point arithmetic ----------------------------------------
int  mw_ge_frombytes_vartime(mw_ge_p3* h, const mw_point_t* p); // 0 = ok
void mw_ge_p3_tobytes(mw_point_t* out, const mw_ge_p3* h);
void mw_ge_p2_tobytes(mw_point_t* out, const mw_ge_p2* h);
void mw_ge_p3_to_cached(mw_ge_cached* r, const mw_ge_p3* p);
void mw_ge_p1p1_to_p3(mw_ge_p3* r, const mw_ge_p1p1* p);
void mw_ge_p1p1_to_p2(mw_ge_p2* r, const mw_ge_p1p1* p);
void mw_ge_p3_0(mw_ge_p3* h);
void mw_ge_add(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_cached* q);
void mw_ge_sub(mw_ge_p1p1* r, const mw_ge_p3* p, const mw_ge_cached* q);
void mw_ge_p3_dbl(mw_ge_p1p1* r, const mw_ge_p3* p);
void mw_ge_mul8(mw_ge_p1p1* r, const mw_ge_p2* p);           // cofactor clearing

// R = a*G  (constant time)
void mw_ge_scalarmult_base(mw_ge_p3* r, const mw_scalar_t* a);
// R = a*P  (constant time; used on secret scalars)
void mw_ge_scalarmult(mw_ge_p3* r, const mw_scalar_t* a, const mw_ge_p3* p);
// R = a*P + b*G  (variable time, public data only)
void mw_ge_double_scalarmult_base_vartime(mw_ge_p2* r, const mw_scalar_t* a,
                                          const mw_ge_p3* p, const mw_scalar_t* b);
// R = a*P + b*Q  (variable time, public data only)
void mw_ge_double_scalarmult_vartime(mw_ge_p2* r, const mw_scalar_t* a,
                                     const mw_ge_p3* p, const mw_scalar_t* b,
                                     const mw_ge_p3* q);

// Byte-level helpers operating on compressed points.
int  mw_point_add(mw_point_t* r, const mw_point_t* a, const mw_point_t* b);
int  mw_point_sub(mw_point_t* r, const mw_point_t* a, const mw_point_t* b);
int  mw_point_scalarmult(mw_point_t* r, const mw_scalar_t* a, const mw_point_t* p);
void mw_point_scalarmult_base(mw_point_t* r, const mw_scalar_t* a);
int  mw_point_is_identity(const mw_point_t* p);
int  mw_point_eq(const mw_point_t* a, const mw_point_t* b);

// ---------------- validation (TZ 8.3) --------------------------------------
// NOTE ON THE RETURN CONVENTION: these three return a BOOLEAN - 1 means the
// point passed, 0 means it failed. They do NOT return mw_err_t, where 0 would
// mean success. Comparing one of them against MW_OK inverts the check and
// silently accepts every malicious point, so do not do it.
//
// Point decodes to a valid curve point.
int mw_point_is_valid(const mw_point_t* p);
// Point is in the prime-order subgroup: l*P == identity. MANDATORY for every
// point that arrives from outside the device.
// The identity itself IS in the main subgroup - use mw_point_check_public()
// when a degenerate public key must also be refused.
int mw_point_in_main_subgroup(const mw_point_t* p);
// Valid, in the main subgroup, and not the identity. This is the check to
// apply to any point read out of a file. Returns 1 when the point is safe.
int mw_point_check_public(const mw_point_t* p);

// ---------------- Monero-specific ------------------------------------------
// hash_to_point / ge_fromfe_frombytes_vartime + mul8. Used for key images.
void mw_hash_to_ec(const uint8_t* data, size_t len, mw_ge_p3* out);
void mw_hash_to_point(const uint8_t* data, size_t len, mw_point_t* out);

// Pedersen commitment C = a*G + b*H  (a = mask/blinding, b = amount).
void mw_commit(mw_point_t* out, const mw_scalar_t* mask, const mw_scalar_t* amount);
// b*H only.
void mw_scalarmult_H(mw_point_t* out, const mw_scalar_t* b);
// Deterministic generator chain used by Bulletproofs+ (get_exponent):
//
//   out = mul8(fromfe(keccak(keccak(H_bytes || "bulletproof_plus" ||
//                                   varint(idx)))))
//
// Note BOTH details, which differ from legacy Bulletproofs: the domain
// separator is "bulletproof_plus" (not "bulletproof"), and the hash is
// applied TWICE - Monero's get_exponent() hashes the concatenation and then
// feeds that digest to hash_to_p3(), which hashes again before mapping to the
// curve. Using the legacy single-hash "bulletproof" chain produces generators
// that verify locally but yield proofs the network rejects.
void mw_bp_get_exponent(mw_point_t* out, uint32_t idx);

#ifdef __cplusplus
}
#endif
#endif
