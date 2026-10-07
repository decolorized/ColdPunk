// Uniform Resources (Blockchain Commons) - animated QR transport (TZ 3.7).
//
// This is a from-scratch C11 implementation of the UR encoding used by
// Feather (>= 2.6.0) and ANON/NERO:
//
//   * Bytewords "minimal" (BCR-2020-012) with a trailing CRC-32;
//   * the `ur:<type>/<bytewords>` and `ur:<type>/<seq>-<seqLen>/<bytewords>`
//     URI forms (BCR-2020-005);
//   * the multi-part CBOR header [seqNum, seqLen, messageLen, checksum, data];
//   * the Luby-transform fountain code of BCR-2020-005, bit-for-bit compatible
//     with the reference implementation: Xoshiro256** seeded with
//     SHA-256(seqNum_be32 || checksum_be32), the Walker-Vose alias sampler over
//     the 1/i degree distribution, and the Fisher-Yates index shuffle.
//
// Everything here treats its input as hostile: the decoder is fed raw strings
// scanned from QR codes. All buffers are bounded, all lengths are validated,
// and the only allocations are made once per session from values that have
// already been clamped against the caller-supplied output capacity.
//
// SPDX-License-Identifier: MIT

#include "ur.h"
#include "../crypto/hash.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Tunables / hard caps
// ---------------------------------------------------------------------------

// BCR-2020-005 uses a minimum fragment length of 10 bytes.
#define UR_MIN_FRAGMENT       10
// "bytes", "crypto-keyimage", ... - a UR type is [a-z0-9-]{1,UR_MAX_TYPE}.
#define UR_MAX_TYPE           32
// Fragment length the fountain search may legitimately overshoot to
// (find_nominal_fragment_length() can exceed max_fragment by a few bytes for
// awkward message lengths); anything beyond this is rejected as hostile.
#define UR_FRAGMENT_SLACK     32
#define UR_MAX_FRAGMENT_HARD  (MW_UR_MAX_FRAGMENT + UR_FRAGMENT_SLACK)
// Mixed (degree > 1) parts retained by the decoder. Dropping mixed parts can
// never stall decoding: the reference encoder emits the seqLen "pure" parts
// first and repeats them every 2^32 sequence numbers, so a pure part for every
// fragment always arrives eventually.
#define UR_MAX_MIXED          32
// Longest CBOR head we ever emit or accept (1 tag byte + 8 length bytes).
#define UR_CBOR_HEAD_MAX      9
// array(5) + 4 * uint + bstr head
#define UR_PART_HEADER_MAX    (1 + 4 * UR_CBOR_HEAD_MAX + UR_CBOR_HEAD_MAX)

#define UR_BITS_WORDS         ((MW_UR_MAX_PARTS + 7) / 8)

typedef struct { uint8_t b[UR_BITS_WORDS]; } ur_bits;

static void bits_clear(ur_bits* s) { memset(s->b, 0, sizeof s->b); }
static bool bits_get(const ur_bits* s, uint32_t i) {
    return (i < MW_UR_MAX_PARTS) && ((s->b[i >> 3] >> (i & 7)) & 1u);
}
static void bits_set(ur_bits* s, uint32_t i) {
    if (i < MW_UR_MAX_PARTS) s->b[i >> 3] |= (uint8_t)(1u << (i & 7));
}
static void bits_unset(ur_bits* s, uint32_t i) {
    if (i < MW_UR_MAX_PARTS) s->b[i >> 3] &= (uint8_t)~(1u << (i & 7));
}
static bool bits_equal(const ur_bits* a, const ur_bits* b) {
    return memcmp(a->b, b->b, sizeof a->b) == 0;
}
static uint32_t bits_count(const ur_bits* s) {
    uint32_t n = 0;
    for (size_t i = 0; i < sizeof s->b; i++) {
        uint8_t v = s->b[i];
        while (v) { n += (uint32_t)(v & 1u); v = (uint8_t)(v >> 1); }
    }
    return n;
}
static uint32_t bits_first(const ur_bits* s) {
    for (uint32_t i = 0; i < MW_UR_MAX_PARTS; i++) if (bits_get(s, i)) return i;
    return UINT32_MAX;
}
// True when `a` is a strict (proper) subset of `b`.
static bool bits_strict_subset(const ur_bits* a, const ur_bits* b) {
    bool proper = false;
    for (size_t i = 0; i < sizeof a->b; i++) {
        if (a->b[i] & (uint8_t)~b->b[i]) return false;   // a has a bit b lacks
        if (a->b[i] != b->b[i]) proper = true;
    }
    return proper;
}
static void bits_subtract(ur_bits* a, const ur_bits* b) {
    for (size_t i = 0; i < sizeof a->b; i++) a->b[i] &= (uint8_t)~b->b[i];
}

static size_t ur_strnlen(const char* s, size_t max) {
    size_t n = 0;
    while (n < max && s[n]) n++;
    return n;
}

static void xor_into(uint8_t* dst, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) - UR's checksum.
// Implemented locally so ur.c never depends on the crypto module's CRC.
// ---------------------------------------------------------------------------

uint32_t mw_ur_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    if (!data) return 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
    }
    return crc ^ 0xFFFFFFFFu;
}

static void be32_put(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

// ---------------------------------------------------------------------------
// Bytewords (BCR-2020-012)
// ---------------------------------------------------------------------------
//
// The canonical 256-word table. Each word is four letters; the first and last
// letters of every word form a unique pair, which is exactly what the
// "minimal" style transmits.

static const char UR_BYTEWORDS[] =
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabias"
    "bluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcost"
    "cruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdull"
    "dutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfish"
    "fizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow"
    "goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhope"
    "hornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl"
    "judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamb"
    "lavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany"
    "mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote"
    "numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose"
    "puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinruns"
    "rustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask"
    "taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser"
    "vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs"
    "whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

// (first letter, last letter) -> byte value, or -1. Built on first use.
static int16_t ur_bw_lut[26 * 26];
static bool    ur_bw_lut_ready = false;

static void bw_lut_init(void) {
    if (ur_bw_lut_ready) return;
    for (size_t i = 0; i < sizeof ur_bw_lut / sizeof ur_bw_lut[0]; i++)
        ur_bw_lut[i] = -1;
    for (int i = 0; i < 256; i++) {
        const char* w = UR_BYTEWORDS + i * 4;
        int x = w[0] - 'a', y = w[3] - 'a';
        ur_bw_lut[(size_t)y * 26 + (size_t)x] = (int16_t)i;
    }
    ur_bw_lut_ready = true;
}

static char lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

// Encodes `len` bytes plus their 4-byte CRC-32 as 2*(len+4) minimal bytewords
// characters. Returns the number of characters written (excluding the NUL), or
// 0 if `out_cap` is too small.
size_t mw_bytewords_encode_minimal(const uint8_t* in, size_t len,
                                   char* out, size_t out_cap) {
    if (!in || !out) return 0;
    if (len > SIZE_MAX / 2 - 8) return 0;
    size_t need = (len + 4) * 2;
    if (out_cap < need + 1) return 0;

    uint8_t crc[4];
    be32_put(crc, mw_ur_crc32(in, len));

    size_t o = 0;
    for (size_t i = 0; i < len + 4; i++) {
        uint8_t b = (i < len) ? in[i] : crc[i - len];
        const char* w = UR_BYTEWORDS + (size_t)b * 4;
        out[o++] = w[0];
        out[o++] = w[3];
    }
    out[o] = '\0';
    return o;
}

// Decodes a minimal-bytewords string (case insensitive) and verifies the
// trailing CRC-32. `out_len` receives the payload length (CRC stripped).
mw_err_t mw_bytewords_decode_minimal(const char* in, uint8_t* out, size_t out_cap,
                                     size_t* out_len) {
    if (!in || !out || !out_len) return MW_ERR_INVALID_ARG;
    bw_lut_init();

    // Bound the scan: out_cap payload bytes + 4 CRC bytes, 2 chars each.
    if (out_cap > (SIZE_MAX / 2) - 8) return MW_ERR_INVALID_ARG;
    size_t max_chars = (out_cap + 4) * 2;
    size_t n = ur_strnlen(in, max_chars + 1);
    if (n > max_chars) return MW_ERR_TOO_MANY;
    if (n < 10 || (n & 1u)) return MW_ERR_FORMAT;    // >= 1 data byte + CRC

    size_t count = n / 2;                            // total bytes incl. CRC
    size_t payload = count - 4;
    if (payload > out_cap) return MW_ERR_TOO_MANY;

    uint8_t crc_in[4];
    for (size_t i = 0; i < count; i++) {
        int x = lc(in[i * 2])     - 'a';
        int y = lc(in[i * 2 + 1]) - 'a';
        if (x < 0 || x >= 26 || y < 0 || y >= 26) return MW_ERR_FORMAT;
        int16_t v = ur_bw_lut[(size_t)y * 26 + (size_t)x];
        if (v < 0) return MW_ERR_FORMAT;
        if (i < payload) out[i] = (uint8_t)v;
        else             crc_in[i - payload] = (uint8_t)v;
    }

    uint8_t crc[4];
    be32_put(crc, mw_ur_crc32(out, payload));
    if (memcmp(crc, crc_in, 4) != 0) return MW_ERR_CHECKSUM;

    *out_len = payload;
    return MW_OK;
}

// ---------------------------------------------------------------------------
// Minimal CBOR (only what the UR part header needs)
// ---------------------------------------------------------------------------

#define CBOR_UINT  0
#define CBOR_BYTES 2
#define CBOR_ARRAY 4

static size_t cbor_head_len(uint64_t v) {
    if (v < 24)         return 1;
    if (v <= 0xFF)      return 2;
    if (v <= 0xFFFF)    return 3;
    if (v <= 0xFFFFFFFF) return 5;
    return 9;
}

// Writes a canonical (shortest-form) CBOR head. Caller guarantees capacity.
static size_t cbor_put_head(uint8_t* out, uint8_t major, uint64_t v) {
    uint8_t m = (uint8_t)(major << 5);
    if (v < 24)          { out[0] = (uint8_t)(m | v); return 1; }
    if (v <= 0xFF)       { out[0] = (uint8_t)(m | 24); out[1] = (uint8_t)v; return 2; }
    if (v <= 0xFFFF)     { out[0] = (uint8_t)(m | 25); out[1] = (uint8_t)(v >> 8);
                           out[2] = (uint8_t)v; return 3; }
    if (v <= 0xFFFFFFFF) { out[0] = (uint8_t)(m | 26);
                           out[1] = (uint8_t)(v >> 24); out[2] = (uint8_t)(v >> 16);
                           out[3] = (uint8_t)(v >> 8);  out[4] = (uint8_t)v; return 5; }
    out[0] = (uint8_t)(m | 27);
    for (int i = 0; i < 8; i++) out[1 + i] = (uint8_t)(v >> (56 - 8 * i));
    return 9;
}

// Reads a CBOR head. Non-canonical lengths are accepted (the reference decoder
// accepts them too); indefinite lengths and reserved additional values are not.
static bool cbor_get_head(const uint8_t* buf, size_t len, size_t* pos,
                          uint8_t* major, uint64_t* val) {
    if (*pos >= len) return false;
    uint8_t b = buf[*pos];
    uint8_t add = b & 0x1Fu;
    *major = (uint8_t)(b >> 5);
    (*pos)++;
    if (add < 24) { *val = add; return true; }
    size_t nbytes;
    switch (add) {
        case 24: nbytes = 1; break;
        case 25: nbytes = 2; break;
        case 26: nbytes = 4; break;
        case 27: nbytes = 8; break;
        default: return false;                // 28..30 reserved, 31 indefinite
    }
    if (len - *pos < nbytes) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes; i++) v = (v << 8) | buf[*pos + i];
    *pos += nbytes;
    *val = v;
    return true;
}

// ---------------------------------------------------------------------------
// Xoshiro256** seeded exactly as BCR-2020-005 does
// ---------------------------------------------------------------------------

typedef struct { uint64_t s[4]; } ur_rng;

static uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

static void rng_seed_bytes(ur_rng* r, const uint8_t* data, size_t len) {
    uint8_t digest[MW_SHA256_DIGEST];
    mw_sha256(data, len, digest);
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int n = 0; n < 8; n++) v = (v << 8) | digest[i * 8 + n];
        r->s[i] = v;
    }
}

static uint64_t rng_next(ur_rng* r) {
    const uint64_t result = rotl64(r->s[1] * 5, 7) * 9;
    const uint64_t t = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl64(r->s[3], 45);
    return result;
}

static double rng_next_double(ur_rng* r) {
    // ((double)UINT64_MAX) + 1.0 == 2^64 exactly, as in the reference.
    const double m = ((double)UINT64_MAX) + 1.0;
    return (double)rng_next(r) / m;
}

static uint64_t rng_next_int(ur_rng* r, uint64_t low, uint64_t high) {
    return (uint64_t)(rng_next_double(r) * (double)(high - low + 1)) + low;
}

// ---------------------------------------------------------------------------
// Fountain helpers
// ---------------------------------------------------------------------------

// Working set for the Walker-Vose alias sampler and the index shuffle. Sized
// once from seqLen (which is clamped to MW_UR_MAX_PARTS) so no allocation ever
// tracks attacker-controlled input beyond that cap.
typedef struct {
    uint32_t n;
    double*  prob;     // alias-table probabilities
    double*  P;        // scaled probabilities (scratch)
    int32_t* alias;
    int32_t* stackS;
    int32_t* stackL;
    uint32_t* idx;     // shuffle scratch
    void*    block;
} ur_scratch;

static void scratch_free(ur_scratch* sc) {
    if (sc->block) free(sc->block);
    memset(sc, 0, sizeof *sc);
}

static bool scratch_alloc(ur_scratch* sc, uint32_t n) {
    memset(sc, 0, sizeof *sc);
    if (n == 0 || n > MW_UR_MAX_PARTS) return false;
    size_t dbl  = (size_t)n * sizeof(double);
    size_t i32  = (size_t)n * sizeof(int32_t);
    size_t u32  = (size_t)n * sizeof(uint32_t);
    size_t total = 2 * dbl + 3 * i32 + u32;
    uint8_t* p = (uint8_t*)malloc(total);
    if (!p) return false;
    sc->block  = p;
    sc->n      = n;
    sc->prob   = (double*)(void*)p;              p += dbl;
    sc->P      = (double*)(void*)p;              p += dbl;
    sc->alias  = (int32_t*)(void*)p;             p += i32;
    sc->stackS = (int32_t*)(void*)p;             p += i32;
    sc->stackL = (int32_t*)(void*)p;             p += i32;
    sc->idx    = (uint32_t*)(void*)p;
    return true;
}

// Walker-Vose alias method over the degree distribution 1/1, 1/2 ... 1/n,
// following the reference construction (including its reversed index order).
static void sampler_build(ur_scratch* sc, uint32_t n) {
    double sum = 0.0;
    for (uint32_t i = 1; i <= n; i++) sum = sum + 1.0 / (double)i;
    for (uint32_t i = 0; i < n; i++)
        sc->P[i] = (1.0 / (double)(i + 1)) * (double)n / sum;

    int32_t ns = 0, nl = 0;
    for (int32_t i = (int32_t)n - 1; i >= 0; i--) {
        if (sc->P[i] < 1.0) sc->stackS[ns++] = i;
        else                sc->stackL[nl++] = i;
    }
    for (uint32_t i = 0; i < n; i++) { sc->prob[i] = 0.0; sc->alias[i] = 0; }

    while (ns > 0 && nl > 0) {
        int32_t a = sc->stackS[--ns];
        int32_t g = sc->stackL[--nl];
        sc->prob[a]  = sc->P[a];
        sc->alias[a] = g;
        sc->P[g] += sc->P[a] - 1.0;
        if (sc->P[g] < 1.0) sc->stackS[ns++] = g;
        else                sc->stackL[nl++] = g;
    }
    while (nl > 0) sc->prob[sc->stackL[--nl]] = 1.0;
    while (ns > 0) sc->prob[sc->stackS[--ns]] = 1.0;
}

static uint32_t sampler_next(const ur_scratch* sc, uint32_t n, ur_rng* rng) {
    double r1 = rng_next_double(rng);
    double r2 = rng_next_double(rng);
    uint32_t i = (uint32_t)((double)n * r1);
    if (i >= n) i = n - 1;                       // r1 < 1 always; belt & braces
    return (r2 < sc->prob[i]) ? i : (uint32_t)sc->alias[i];
}

static uint32_t ur_choose_degree(uint32_t seq_len, ur_rng* rng, ur_scratch* sc) {
    sampler_build(sc, seq_len);
    return sampler_next(sc, seq_len, rng) + 1;
}

// Fills `out` with the fragment indexes mixed into part `seq_num`.
static void ur_choose_fragments(uint32_t seq_num, uint32_t seq_len,
                                uint32_t checksum, ur_bits* out,
                                uint32_t* out_count, ur_scratch* sc) {
    bits_clear(out);
    if (seq_num <= seq_len) {                    // the "pure" parts
        bits_set(out, seq_num - 1);
        if (out_count) *out_count = 1;
        return;
    }
    uint8_t seed[8];
    be32_put(seed, seq_num);
    be32_put(seed + 4, checksum);

    ur_rng rng;
    rng_seed_bytes(&rng, seed, sizeof seed);

    uint32_t degree = ur_choose_degree(seq_len, &rng, sc);
    if (degree > seq_len) degree = seq_len;

    for (uint32_t i = 0; i < seq_len; i++) sc->idx[i] = i;
    uint32_t remaining = seq_len;
    for (uint32_t k = 0; k < degree; k++) {
        uint32_t pick = (uint32_t)rng_next_int(&rng, 0, remaining - 1);
        if (pick >= remaining) pick = remaining - 1;
        bits_set(out, sc->idx[pick]);
        memmove(&sc->idx[pick], &sc->idx[pick + 1],
                (size_t)(remaining - pick - 1) * sizeof(uint32_t));
        remaining--;
    }
    if (out_count) *out_count = degree;
}

// BCR-2020-005 find_nominal_fragment_length().
static size_t ur_nominal_fragment_len(size_t message_len, size_t min_len,
                                      size_t max_len) {
    if (message_len == 0 || min_len == 0 || max_len < min_len) return 0;
    if (message_len <= max_len) return message_len;
    size_t max_count = message_len / min_len;
    size_t frag = message_len;
    for (size_t count = 1; count <= max_count; count++) {
        frag = (message_len + count - 1) / count;      // ceil
        if (frag <= max_len) break;
    }
    return frag;
}

// ---------------------------------------------------------------------------
// UR type / URI helpers
// ---------------------------------------------------------------------------

static bool ur_type_valid(const char* t, size_t* len_out) {
    if (!t) return false;
    size_t n = ur_strnlen(t, UR_MAX_TYPE + 1);
    if (n == 0 || n > UR_MAX_TYPE) return false;
    for (size_t i = 0; i < n; i++) {
        char c = t[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    if (len_out) *len_out = n;
    return true;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

struct mw_ur_encoder {
    char       type[UR_MAX_TYPE + 1];
    size_t     type_len;
    uint8_t*   message;        // CBOR message, zero-padded to seq_len*frag_len
    size_t     message_len;    // unpadded length
    size_t     frag_len;
    uint32_t   seq_len;
    uint32_t   seq_num;
    uint32_t   checksum;
    uint8_t*   mix;            // frag_len scratch
    ur_scratch sc;
};

mw_ur_encoder* mw_ur_encoder_new(const char* ur_type, const uint8_t* payload,
                                 size_t len, size_t max_fragment) {
    size_t type_len = 0;
    if (!ur_type_valid(ur_type, &type_len)) return NULL;
    if (!payload || len == 0) return NULL;
    if (len > 0xFFFFFFFFu) return NULL;

    if (max_fragment == 0) max_fragment = MW_UR_DEFAULT_FRAGMENT;
    if (max_fragment < UR_MIN_FRAGMENT) max_fragment = UR_MIN_FRAGMENT;
    if (max_fragment > MW_UR_MAX_FRAGMENT) max_fragment = MW_UR_MAX_FRAGMENT;

    mw_ur_encoder* e = (mw_ur_encoder*)calloc(1, sizeof *e);
    if (!e) return NULL;
    memcpy(e->type, ur_type, type_len);
    e->type[type_len] = '\0';
    e->type_len = type_len;

    // message = CBOR byte string wrapping the payload.
    size_t head = cbor_head_len((uint64_t)len);
    size_t mlen = head + len;
    e->message_len = mlen;

    size_t frag = ur_nominal_fragment_len(mlen, UR_MIN_FRAGMENT, max_fragment);
    if (frag == 0) { free(e); return NULL; }
    size_t seq_len = (mlen + frag - 1) / frag;
    if (seq_len == 0 || seq_len > MW_UR_MAX_PARTS) { free(e); return NULL; }

    size_t padded = seq_len * frag;
    e->message = (uint8_t*)calloc(1, padded);
    if (!e->message) { free(e); return NULL; }
    cbor_put_head(e->message, CBOR_BYTES, (uint64_t)len);
    memcpy(e->message + head, payload, len);

    e->frag_len = frag;
    e->seq_len  = (uint32_t)seq_len;
    e->seq_num  = 0;
    e->checksum = mw_ur_crc32(e->message, mlen);

    e->mix = (uint8_t*)malloc(frag);
    if (!e->mix) { free(e->message); free(e); return NULL; }
    if (seq_len > 1 && !scratch_alloc(&e->sc, e->seq_len)) {
        free(e->mix); free(e->message); free(e); return NULL;
    }
    return e;
}

void mw_ur_encoder_free(mw_ur_encoder* e) {
    if (!e) return;
    scratch_free(&e->sc);
    if (e->mix) free(e->mix);
    if (e->message) free(e->message);
    free(e);
}

uint32_t mw_ur_encoder_seq_len(const mw_ur_encoder* e) {
    return e ? e->seq_len : 0;
}

bool mw_ur_encoder_is_single_part(const mw_ur_encoder* e) {
    return e && e->seq_len == 1;
}

size_t mw_ur_encoder_next(mw_ur_encoder* e, char* out, size_t out_cap) {
    if (!e || !out || out_cap == 0) return 0;

    e->seq_num++;                       // wraps at 2^32, exactly as upstream

    if (e->seq_len == 1) {
        // ur:<type>/<bytewords(message)>
        size_t need = 3 + e->type_len + 1 + (e->message_len + 4) * 2 + 1;
        if (out_cap < need) return 0;
        int n = snprintf(out, out_cap, "ur:%s/", e->type);
        if (n < 0 || (size_t)n >= out_cap) return 0;
        size_t w = mw_bytewords_encode_minimal(e->message, e->message_len,
                                               out + n, out_cap - (size_t)n);
        if (w == 0) return 0;
        return (size_t)n + w;
    }

    ur_bits idx;
    ur_choose_fragments(e->seq_num, e->seq_len, e->checksum, &idx, NULL, &e->sc);

    memset(e->mix, 0, e->frag_len);
    for (uint32_t i = 0; i < e->seq_len; i++)
        if (bits_get(&idx, i))
            xor_into(e->mix, e->message + (size_t)i * e->frag_len, e->frag_len);

    // CBOR [seqNum, seqLen, messageLen, checksum, data]
    uint8_t hdr[UR_PART_HEADER_MAX];
    size_t p = 0;
    p += cbor_put_head(hdr + p, CBOR_ARRAY, 5);
    p += cbor_put_head(hdr + p, CBOR_UINT,  e->seq_num);
    p += cbor_put_head(hdr + p, CBOR_UINT,  e->seq_len);
    p += cbor_put_head(hdr + p, CBOR_UINT,  (uint64_t)e->message_len);
    p += cbor_put_head(hdr + p, CBOR_UINT,  e->checksum);
    p += cbor_put_head(hdr + p, CBOR_BYTES, (uint64_t)e->frag_len);

    size_t part_len = p + e->frag_len;
    uint8_t* part = (uint8_t*)malloc(part_len);
    if (!part) return 0;
    memcpy(part, hdr, p);
    memcpy(part + p, e->mix, e->frag_len);

    int n = snprintf(out, out_cap, "ur:%s/%u-%u/", e->type,
                     (unsigned)e->seq_num, (unsigned)e->seq_len);
    if (n < 0 || (size_t)n >= out_cap) { free(part); return 0; }
    size_t w = mw_bytewords_encode_minimal(part, part_len,
                                           out + n, out_cap - (size_t)n);
    free(part);
    if (w == 0) return 0;
    return (size_t)n + w;
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

typedef struct {
    ur_bits  idx;
    uint32_t count;
    uint8_t* data;         // points into mixed_pool
    bool     used;
} ur_mixed_part;

struct mw_ur_decoder {
    uint8_t*  out;
    size_t    out_cap;

    char      type[UR_MAX_TYPE + 1];
    bool      have_type;

    bool      have_header;
    uint32_t  seq_len;
    size_t    frag_len;
    size_t    message_len;
    uint32_t  checksum;

    uint8_t*  frags;        // seq_len * frag_len
    ur_bits   received;
    uint32_t  received_count;

    ur_mixed_part mixed[UR_MAX_MIXED];
    uint8_t*  mixed_pool;   // UR_MAX_MIXED * frag_len
    int       mixed_count;

    uint8_t*  scratch;      // frag_len
    ur_scratch sc;

    bool      complete;
    bool      failed;
    size_t    result_off;
    size_t    result_len;
    uint32_t  processed;
};

mw_ur_decoder* mw_ur_decoder_new(uint8_t* buffer, size_t buffer_cap) {
    if (!buffer || buffer_cap == 0) return NULL;
    mw_ur_decoder* d = (mw_ur_decoder*)calloc(1, sizeof *d);
    if (!d) return NULL;
    d->out = buffer;
    d->out_cap = buffer_cap;
    return d;
}

void mw_ur_decoder_free(mw_ur_decoder* d) {
    if (!d) return;
    scratch_free(&d->sc);
    if (d->frags) free(d->frags);
    if (d->mixed_pool) free(d->mixed_pool);
    if (d->scratch) free(d->scratch);
    free(d);
}

bool mw_ur_decoder_complete(const mw_ur_decoder* d) {
    return d && d->complete && !d->failed;
}

int mw_ur_decoder_progress_permille(const mw_ur_decoder* d) {
    if (!d) return 0;
    if (d->complete && !d->failed) return 1000;
    if (!d->have_header || d->seq_len == 0) return 0;
    uint32_t p = (uint32_t)(((uint64_t)d->received_count * 1000u) / d->seq_len);
    return (int)(p > 999 ? 999 : p);
}

// If the whole message is exactly one CBOR byte string, hand back its contents;
// otherwise hand back the raw CBOR. `ur:bytes` (and every UR type this wallet
// ships) is a bare byte string, so callers get the file bytes directly.
static void decoder_set_result(mw_ur_decoder* d) {
    size_t pos = 0;
    uint8_t major;
    uint64_t val;
    d->result_off = 0;
    d->result_len = d->message_len;
    if (cbor_get_head(d->out, d->message_len, &pos, &major, &val) &&
        major == CBOR_BYTES && val <= (uint64_t)(d->message_len - pos) &&
        (size_t)val == d->message_len - pos) {
        d->result_off = pos;
        d->result_len = (size_t)val;
    }
    d->complete = true;
}

static void decoder_finish(mw_ur_decoder* d) {
    memcpy(d->out, d->frags, d->message_len);
    if (mw_ur_crc32(d->out, d->message_len) != d->checksum) {
        d->failed = true;
        d->complete = true;
        return;
    }
    decoder_set_result(d);
}

// Records a fully-reduced (degree 1) fragment.
static void decoder_add_pure(mw_ur_decoder* d, uint32_t index, const uint8_t* data);

// Reduces `idx`/`data` by everything already known. Returns the remaining
// degree.
static uint32_t decoder_reduce(mw_ur_decoder* d, ur_bits* idx, uint8_t* data) {
    for (uint32_t i = 0; i < d->seq_len; i++) {
        if (bits_get(idx, i) && bits_get(&d->received, i)) {
            xor_into(data, d->frags + (size_t)i * d->frag_len, d->frag_len);
            bits_unset(idx, i);
        }
    }
    bool progress = true;
    while (progress) {
        progress = false;
        for (int m = 0; m < UR_MAX_MIXED; m++) {
            if (!d->mixed[m].used) continue;
            if (bits_strict_subset(&d->mixed[m].idx, idx)) {
                xor_into(data, d->mixed[m].data, d->frag_len);
                bits_subtract(idx, &d->mixed[m].idx);
                progress = true;
            }
        }
    }
    return bits_count(idx);
}

static void decoder_add_pure(mw_ur_decoder* d, uint32_t index, const uint8_t* data) {
    if (index >= d->seq_len || bits_get(&d->received, index)) return;
    memcpy(d->frags + (size_t)index * d->frag_len, data, d->frag_len);
    bits_set(&d->received, index);
    d->received_count++;

    if (d->received_count == d->seq_len) { decoder_finish(d); return; }

    // Cascade: reduce every stored mixed part by the new fragment, promoting
    // any that collapse to a single index.
    bool progress = true;
    while (progress && d->received_count < d->seq_len) {
        progress = false;
        for (int m = 0; m < UR_MAX_MIXED; m++) {
            if (!d->mixed[m].used) continue;
            uint32_t deg = decoder_reduce(d, &d->mixed[m].idx, d->mixed[m].data);
            if (deg == 0) {
                d->mixed[m].used = false;
                d->mixed_count--;
                progress = true;
            } else if (deg == 1) {
                uint32_t i = bits_first(&d->mixed[m].idx);
                uint8_t* tmp = d->scratch;
                memcpy(tmp, d->mixed[m].data, d->frag_len);
                d->mixed[m].used = false;
                d->mixed_count--;
                progress = true;
                decoder_add_pure(d, i, tmp);
                if (d->complete) return;
            } else {
                d->mixed[m].count = (uint16_t)deg;
            }
        }
    }
}

static void decoder_store_mixed(mw_ur_decoder* d, const ur_bits* idx,
                                const uint8_t* data, uint32_t degree) {
    for (int m = 0; m < UR_MAX_MIXED; m++)
        if (d->mixed[m].used && bits_equal(&d->mixed[m].idx, idx)) return;
    for (int m = 0; m < UR_MAX_MIXED; m++) {
        if (d->mixed[m].used) continue;
        d->mixed[m].used  = true;
        d->mixed[m].idx   = *idx;
        d->mixed[m].count = (uint16_t)degree;
        d->mixed[m].data  = d->mixed_pool + (size_t)m * d->frag_len;
        memcpy(d->mixed[m].data, data, d->frag_len);
        d->mixed_count++;
        return;
    }
    // Pool full: drop the part. Safe - pure parts always come round again.
}

// Validates the first part's header and allocates the working set.
static mw_err_t decoder_init_header(mw_ur_decoder* d, uint32_t seq_len,
                                    size_t message_len, uint32_t checksum,
                                    size_t frag_len) {
    if (seq_len == 0 || seq_len > MW_UR_MAX_PARTS) return MW_ERR_FORMAT;
    if (frag_len == 0 || frag_len > UR_MAX_FRAGMENT_HARD) return MW_ERR_FORMAT;
    if (message_len == 0 || message_len > d->out_cap) return MW_ERR_TOO_MANY;
    // The reference encoder always satisfies this; enforcing it keeps
    // seq_len * frag_len tied to the caller's capacity.
    if ((size_t)seq_len * frag_len < message_len) return MW_ERR_FORMAT;
    if ((size_t)(seq_len - 1) * frag_len >= message_len) return MW_ERR_FORMAT;

    d->frags = (uint8_t*)calloc(1, (size_t)seq_len * frag_len);
    d->mixed_pool = (uint8_t*)calloc(UR_MAX_MIXED, frag_len);
    d->scratch = (uint8_t*)malloc(frag_len);
    if (!d->frags || !d->mixed_pool || !d->scratch) {
        if (d->frags) { free(d->frags); d->frags = NULL; }
        if (d->mixed_pool) { free(d->mixed_pool); d->mixed_pool = NULL; }
        if (d->scratch) { free(d->scratch); d->scratch = NULL; }
        return MW_ERR_MEMORY;
    }
    if (seq_len > 1 && !scratch_alloc(&d->sc, seq_len)) {
        free(d->frags); d->frags = NULL;
        free(d->mixed_pool); d->mixed_pool = NULL;
        free(d->scratch); d->scratch = NULL;
        return MW_ERR_MEMORY;
    }
    d->seq_len     = seq_len;
    d->frag_len    = frag_len;
    d->message_len = message_len;
    d->checksum    = checksum;
    d->have_header = true;
    return MW_OK;
}

// Parses "ur:<type>/..." and dispatches. Case insensitive.
mw_err_t mw_ur_decoder_receive(mw_ur_decoder* d, const char* part) {
    if (!d || !part) return MW_ERR_INVALID_ARG;
    if (d->complete) return MW_OK;

    // A single-part UR carries out_cap+overhead payload bytes; a multi-part one
    // is far shorter. Bound the scan accordingly.
    size_t limit = 3 + UR_MAX_TYPE + 1 + 24 + (d->out_cap + UR_CBOR_HEAD_MAX + 4) * 2 + 8;
    size_t n = ur_strnlen(part, limit + 1);
    if (n > limit || n < 5) return MW_ERR_FORMAT;

    if (!(lc(part[0]) == 'u' && lc(part[1]) == 'r' && part[2] == ':'))
        return MW_ERR_FORMAT;

    const char* p = part + 3;
    const char* slash = strchr(p, '/');
    if (!slash) return MW_ERR_FORMAT;
    size_t tlen = (size_t)(slash - p);
    if (tlen == 0 || tlen > UR_MAX_TYPE) return MW_ERR_FORMAT;

    char type[UR_MAX_TYPE + 1];
    for (size_t i = 0; i < tlen; i++) type[i] = lc(p[i]);
    type[tlen] = '\0';
    if (!ur_type_valid(type, NULL)) return MW_ERR_FORMAT;

    if (!d->have_type) { memcpy(d->type, type, tlen + 1); d->have_type = true; }
    else if (strcmp(d->type, type) != 0) return MW_ERR_FORMAT;

    const char* body = slash + 1;
    const char* slash2 = strchr(body, '/');

    // ---- single part -------------------------------------------------------
    if (!slash2) {
        size_t mlen = 0;
        mw_err_t err = mw_bytewords_decode_minimal(body, d->out, d->out_cap, &mlen);
        if (err != MW_OK) return err;
        if (mlen == 0) return MW_ERR_FORMAT;
        d->seq_len = 1;
        d->message_len = mlen;
        d->received_count = 1;
        d->have_header = true;
        d->processed++;
        decoder_set_result(d);
        return MW_OK;
    }

    // ---- multi part --------------------------------------------------------
    if (strchr(slash2 + 1, '/')) return MW_ERR_FORMAT;   // too many components

    // "<seqNum>-<seqLen>"
    size_t seqlen_chars = (size_t)(slash2 - body);
    if (seqlen_chars == 0 || seqlen_chars > 21) return MW_ERR_FORMAT;
    uint64_t uri_seq_num = 0, uri_seq_len = 0;
    size_t i = 0;
    if (!(body[i] >= '0' && body[i] <= '9')) return MW_ERR_FORMAT;
    for (; i < seqlen_chars && body[i] >= '0' && body[i] <= '9'; i++) {
        uri_seq_num = uri_seq_num * 10 + (uint64_t)(body[i] - '0');
        if (uri_seq_num > 0xFFFFFFFFu) return MW_ERR_FORMAT;
    }
    if (i >= seqlen_chars || body[i] != '-') return MW_ERR_FORMAT;
    i++;
    if (i >= seqlen_chars) return MW_ERR_FORMAT;
    for (; i < seqlen_chars; i++) {
        if (!(body[i] >= '0' && body[i] <= '9')) return MW_ERR_FORMAT;
        uri_seq_len = uri_seq_len * 10 + (uint64_t)(body[i] - '0');
        if (uri_seq_len > MW_UR_MAX_PARTS) return MW_ERR_FORMAT;
    }
    if (uri_seq_num < 1 || uri_seq_len < 1) return MW_ERR_FORMAT;

    // The CBOR part is a header plus one fragment; nothing else is acceptable.
    uint8_t cbor[UR_PART_HEADER_MAX + UR_MAX_FRAGMENT_HARD];
    size_t cbor_len = 0;
    mw_err_t err = mw_bytewords_decode_minimal(slash2 + 1, cbor, sizeof cbor,
                                               &cbor_len);
    if (err != MW_OK) return err;

    size_t pos = 0;
    uint8_t major;
    uint64_t val;
    if (!cbor_get_head(cbor, cbor_len, &pos, &major, &val) ||
        major != CBOR_ARRAY || val != 5) return MW_ERR_FORMAT;

    uint64_t f[4];
    for (int k = 0; k < 4; k++) {
        if (!cbor_get_head(cbor, cbor_len, &pos, &major, &val) ||
            major != CBOR_UINT || val > 0xFFFFFFFFu) return MW_ERR_FORMAT;
        f[k] = val;
    }
    if (!cbor_get_head(cbor, cbor_len, &pos, &major, &val) ||
        major != CBOR_BYTES) return MW_ERR_FORMAT;
    if (val > (uint64_t)(cbor_len - pos)) return MW_ERR_FORMAT;

    uint32_t seq_num  = (uint32_t)f[0];
    uint32_t seq_len  = (uint32_t)f[1];
    size_t   msg_len  = (size_t)f[2];
    uint32_t checksum = (uint32_t)f[3];
    size_t   frag_len = (size_t)val;
    const uint8_t* frag = cbor + pos;

    if (seq_num != (uint32_t)uri_seq_num || seq_len != (uint32_t)uri_seq_len)
        return MW_ERR_FORMAT;
    if (seq_num < 1) return MW_ERR_FORMAT;

    if (!d->have_header) {
        err = decoder_init_header(d, seq_len, msg_len, checksum, frag_len);
        if (err != MW_OK) return err;
    } else {
        if (d->seq_len != seq_len || d->message_len != msg_len ||
            d->checksum != checksum || d->frag_len != frag_len)
            return MW_ERR_FORMAT;
    }

    ur_bits idx;
    ur_choose_fragments(seq_num, seq_len, checksum, &idx, NULL, &d->sc);

    memcpy(d->scratch, frag, d->frag_len);
    ur_bits work = idx;
    uint8_t* data = d->scratch;

    // Reduce against what we already know.
    uint32_t deg = decoder_reduce(d, &work, data);
    d->processed++;

    if (deg == 0) return MW_OK;                  // nothing new
    if (deg == 1) {
        uint32_t index = bits_first(&work);
        // decoder_add_pure() may recurse through d->scratch, so copy out first.
        uint8_t stackbuf[UR_MAX_FRAGMENT_HARD];
        memcpy(stackbuf, data, d->frag_len);
        decoder_add_pure(d, index, stackbuf);
        return MW_OK;
    }
    decoder_store_mixed(d, &work, data, deg);
    return MW_OK;
}

mw_err_t mw_ur_decoder_result(mw_ur_decoder* d, const uint8_t** data,
                              size_t* len, char* type_out, size_t type_cap) {
    if (!d) return MW_ERR_INVALID_ARG;
    if (!d->complete) return MW_ERR_FORMAT;
    if (d->failed) return MW_ERR_CHECKSUM;
    if (data) *data = d->out + d->result_off;
    if (len) *len = d->result_len;
    if (type_out && type_cap > 0) {
        size_t n = ur_strnlen(d->type, UR_MAX_TYPE);
        if (n + 1 > type_cap) return MW_ERR_TOO_MANY;
        memcpy(type_out, d->type, n + 1);
    }
    return MW_OK;
}

// ---------------------------------------------------------------------------
// Host-test hooks. These expose the internals that the BCR-2020-005 test
// vectors exercise without widening the frozen public header.
// ---------------------------------------------------------------------------
#ifdef MW_HOST_BUILD

void mw_ur_test_xoshiro(const uint8_t* seed, size_t seed_len,
                        uint64_t* out, size_t n) {
    ur_rng r;
    rng_seed_bytes(&r, seed, seed_len);
    for (size_t i = 0; i < n; i++) out[i] = rng_next(&r);
}

void mw_ur_test_xoshiro_int(const uint8_t* seed, size_t seed_len,
                            uint64_t low, uint64_t high,
                            uint64_t* out, size_t n) {
    ur_rng r;
    rng_seed_bytes(&r, seed, seed_len);
    for (size_t i = 0; i < n; i++) out[i] = rng_next_int(&r, low, high);
}

size_t mw_ur_test_nominal_fragment_len(size_t message_len, size_t min_len,
                                       size_t max_len) {
    return ur_nominal_fragment_len(message_len, min_len, max_len);
}

uint32_t mw_ur_test_choose_degree(uint32_t seq_len, const uint8_t* seed,
                                  size_t seed_len) {
    ur_rng r;
    ur_scratch sc;
    rng_seed_bytes(&r, seed, seed_len);
    if (!scratch_alloc(&sc, seq_len)) return 0;
    uint32_t deg = ur_choose_degree(seq_len, &r, &sc);
    scratch_free(&sc);
    return deg;
}

size_t mw_ur_test_choose_fragments(uint32_t seq_num, uint32_t seq_len,
                                   uint32_t checksum, uint32_t* out,
                                   size_t out_cap) {
    ur_bits idx;
    ur_scratch sc;
    if (!scratch_alloc(&sc, seq_len)) return 0;
    ur_choose_fragments(seq_num, seq_len, checksum, &idx, NULL, &sc);
    scratch_free(&sc);
    size_t n = 0;
    for (uint32_t i = 0; i < seq_len && n < out_cap; i++)
        if (bits_get(&idx, i)) out[n++] = i;
    return n;
}

#endif /* MW_HOST_BUILD */
