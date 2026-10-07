// Self-contained QR Code generator (ISO/IEC 18004), byte mode, versions 1..20,
// error-correction levels L and M, with full mask penalty evaluation.
//
// The algorithm follows the published standard: the block/ECC tables, the
// Reed-Solomon divisor construction over GF(2^8) mod 0x11D, the BCH(15,5)
// format and BCH(18,6) version information codes, the zig-zag codeword
// placement and the four masking penalty rules of clause 7.8.3.
//
// No heap allocation - the largest working buffers (a 1085-byte codeword array
// and a 1261-byte function-module map) live on the stack.
//
// SPDX-License-Identifier: MIT

#include "qr_encode.h"

#include <string.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// Static capacity tables (ISO/IEC 18004 tables 13-22), versions 1..20
// ---------------------------------------------------------------------------

// Error-correction codewords per block.
static const uint8_t QR_ECC_PER_BLOCK[2][MW_QR_MAX_VERSION + 1] = {
    /* L */ { 0,  7, 10, 15, 20, 26, 18, 20, 24, 30, 18,
                 20, 24, 26, 30, 22, 24, 28, 30, 28, 28 },
    /* M */ { 0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26,
                 30, 22, 22, 24, 24, 28, 28, 26, 26, 26 },
};

// Number of error-correction blocks.
static const uint8_t QR_NUM_BLOCKS[2][MW_QR_MAX_VERSION + 1] = {
    /* L */ { 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8 },
    /* M */ { 0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16 },
};

#define QR_MAX_BLOCKS      16
#define QR_MAX_ECC_LEN     30
#define QR_MAX_CODEWORDS   1085          // version 20, all levels

// Penalty weights, clause 7.8.3.1.
#define QR_PENALTY_N1 3
#define QR_PENALTY_N2 3
#define QR_PENALTY_N3 40
#define QR_PENALTY_N4 10

// ---------------------------------------------------------------------------
// Bitmap helpers
// ---------------------------------------------------------------------------

// Bit index of module (x, y): rows are byte-aligned, MW_QR_STRIDE bytes each.
#define QR_BIT_INDEX(x, y) ((size_t)(y) * (MW_QR_STRIDE * 8) + (size_t)(x))

static void bm_set(uint8_t* bm, int size, int x, int y, bool dark) {
    (void)size;
    size_t bit = QR_BIT_INDEX(x, y);
    size_t i = bit >> 3;
    uint8_t m = (uint8_t)(1u << (bit & 7));
    if (dark) bm[i] |= m; else bm[i] &= (uint8_t)~m;
}

static bool bm_get(const uint8_t* bm, int x, int y) {
    size_t bit = QR_BIT_INDEX(x, y);
    return (bm[bit >> 3] >> (bit & 7)) & 1u;
}

static void bm_toggle(uint8_t* bm, int x, int y) {
    size_t bit = QR_BIT_INDEX(x, y);
    bm[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
}

bool mw_qr_get(const mw_qr_t* q, int x, int y) {
    if (!q || x < 0 || y < 0 || x >= q->size || y >= q->size) return false;
    return bm_get(q->modules, x, y);
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

// Total data modules available in `version`, before ECC (clause 7.1 / annex).
static int qr_raw_data_modules(int version) {
    int result = (16 * version + 128) * version + 64;
    if (version >= 2) {
        int num_align = version / 7 + 2;
        result -= (25 * num_align - 10) * num_align - 55;
        if (version >= 7) result -= 36;
    }
    return result;
}

static int qr_data_codewords(int version, mw_qr_ecc_t ecc) {
    return qr_raw_data_modules(version) / 8
         - (int)QR_ECC_PER_BLOCK[ecc][version] * (int)QR_NUM_BLOCKS[ecc][version];
}

size_t mw_qr_byte_capacity(uint8_t version, mw_qr_ecc_t ecc) {
    if (version < MW_QR_MIN_VERSION || version > MW_QR_MAX_VERSION) return 0;
    if (ecc != MW_QR_ECC_L && ecc != MW_QR_ECC_M) return 0;
    int bits = qr_data_codewords(version, ecc) * 8;
    int header = 4 + ((version <= 9) ? 8 : 16);    // mode + character count
    if (bits <= header) return 0;
    return (size_t)((bits - header) / 8);
}

uint8_t mw_qr_min_version(size_t len, mw_qr_ecc_t ecc) {
    for (uint8_t v = MW_QR_MIN_VERSION; v <= MW_QR_MAX_VERSION; v++)
        if (len <= mw_qr_byte_capacity(v, ecc)) return v;
    return 0;
}

// ---------------------------------------------------------------------------
// Reed-Solomon over GF(2^8), primitive polynomial 0x11D
// ---------------------------------------------------------------------------

static uint8_t gf_mul(uint8_t x, uint8_t y) {
    uint8_t z = 0;
    for (int i = 7; i >= 0; i--) {
        z = (uint8_t)((z << 1) ^ (uint8_t)((z >> 7) * 0x1D));
        z ^= (uint8_t)(((y >> i) & 1) * x);
    }
    return z;
}

// Generator polynomial of the given degree (coefficients, highest term first,
// leading 1 implied).
static void rs_divisor(int degree, uint8_t* out) {
    memset(out, 0, (size_t)degree);
    out[degree - 1] = 1;
    uint8_t root = 1;
    for (int i = 0; i < degree; i++) {
        for (int j = 0; j < degree; j++) {
            out[j] = gf_mul(out[j], root);
            if (j + 1 < degree) out[j] ^= out[j + 1];
        }
        root = gf_mul(root, 0x02);
    }
}

static void rs_remainder(const uint8_t* data, int data_len,
                         const uint8_t* divisor, int degree, uint8_t* out) {
    memset(out, 0, (size_t)degree);
    for (int i = 0; i < data_len; i++) {
        uint8_t factor = data[i] ^ out[0];
        memmove(&out[0], &out[1], (size_t)(degree - 1));
        out[degree - 1] = 0;
        for (int j = 0; j < degree; j++) out[j] ^= gf_mul(divisor[j], factor);
    }
}

// ---------------------------------------------------------------------------
// Function patterns
// ---------------------------------------------------------------------------

static int qr_align_positions(int version, uint8_t* out /* >= 7 */) {
    if (version == 1) return 0;
    int n = version / 7 + 2;
    int step = (version * 4 + n * 2 + 1) / (n * 2 - 2) * 2;
    int pos = version * 4 + 10;
    for (int i = n - 1; i >= 1; i--, pos -= step) out[i] = (uint8_t)pos;
    out[0] = 6;
    return n;
}

static void draw_finder(uint8_t* bm, uint8_t* fn, int size, int cx, int cy) {
    for (int dy = -4; dy <= 4; dy++) {
        for (int dx = -4; dx <= 4; dx++) {
            int px = cx + dx, py = cy + dy;
            if (px < 0 || py < 0 || px >= size || py >= size) continue;
            int d = abs(dx) > abs(dy) ? abs(dx) : abs(dy);
            bm_set(bm, size, px, py, d != 2 && d != 4);
            bm_set(fn, size, px, py, true);
        }
    }
}

static void draw_alignment(uint8_t* bm, uint8_t* fn, int size, int cx, int cy) {
    for (int dy = -2; dy <= 2; dy++) {
        for (int dx = -2; dx <= 2; dx++) {
            int d = abs(dx) > abs(dy) ? abs(dx) : abs(dy);
            bm_set(bm, size, cx + dx, cy + dy, d != 1);
            bm_set(fn, size, cx + dx, cy + dy, true);
        }
    }
}

// BCH(15,5) format information, generator 0x537, mask 0x5412 (clause 7.9).
static uint32_t qr_format_bits(mw_qr_ecc_t ecc, int mask) {
    static const uint32_t ECC_FORMAT[2] = { 1, 0 };     // L = 01, M = 00
    uint32_t data = (ECC_FORMAT[ecc] << 3) | (uint32_t)mask;
    uint32_t rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537u);
    return ((data << 10) | rem) ^ 0x5412u;
}

// BCH(18,6) version information, generator 0x1F25 (clause 7.10).
static uint32_t qr_version_bits(int version) {
    uint32_t rem = (uint32_t)version;
    for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25u);
    return ((uint32_t)version << 12) | rem;
}

static void draw_format(uint8_t* bm, uint8_t* fn, int size, mw_qr_ecc_t ecc,
                        int mask) {
    uint32_t bits = qr_format_bits(ecc, mask);
    for (int i = 0; i <= 5; i++) {
        bool b = (bits >> i) & 1u;
        bm_set(bm, size, 8, i, b); bm_set(fn, size, 8, i, true);
    }
    bool b6 = (bits >> 6) & 1u, b7 = (bits >> 7) & 1u, b8 = (bits >> 8) & 1u;
    bm_set(bm, size, 8, 7, b6); bm_set(fn, size, 8, 7, true);
    bm_set(bm, size, 8, 8, b7); bm_set(fn, size, 8, 8, true);
    bm_set(bm, size, 7, 8, b8); bm_set(fn, size, 7, 8, true);
    for (int i = 9; i < 15; i++) {
        bool b = (bits >> i) & 1u;
        bm_set(bm, size, 14 - i, 8, b); bm_set(fn, size, 14 - i, 8, true);
    }
    for (int i = 0; i < 8; i++) {
        bool b = (bits >> i) & 1u;
        bm_set(bm, size, size - 1 - i, 8, b);
        bm_set(fn, size, size - 1 - i, 8, true);
    }
    for (int i = 8; i < 15; i++) {
        bool b = (bits >> i) & 1u;
        bm_set(bm, size, 8, size - 15 + i, b);
        bm_set(fn, size, 8, size - 15 + i, true);
    }
    bm_set(bm, size, 8, size - 8, true);               // permanent dark module
    bm_set(fn, size, 8, size - 8, true);
}

static void draw_function_patterns(uint8_t* bm, uint8_t* fn, int size,
                                   int version, mw_qr_ecc_t ecc) {
    // Timing patterns.
    for (int i = 0; i < size; i++) {
        bm_set(bm, size, 6, i, i % 2 == 0); bm_set(fn, size, 6, i, true);
        bm_set(bm, size, i, 6, i % 2 == 0); bm_set(fn, size, i, 6, true);
    }

    // Finder patterns plus their separators.
    draw_finder(bm, fn, size, 3, 3);
    draw_finder(bm, fn, size, size - 4, 3);
    draw_finder(bm, fn, size, 3, size - 4);

    // Alignment patterns (skipping the three that overlap the finders).
    uint8_t pos[7];
    int n = qr_align_positions(version, pos);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if ((i == 0 && j == 0) || (i == 0 && j == n - 1) ||
                (i == n - 1 && j == 0)) continue;
            draw_alignment(bm, fn, size, pos[i], pos[j]);
        }
    }

    // Format information (mask 0 for now; rewritten once a mask is chosen).
    draw_format(bm, fn, size, ecc, 0);

    // Version information, versions 7 and up.
    if (version >= 7) {
        uint32_t bits = qr_version_bits(version);
        for (int i = 0; i < 18; i++) {
            bool b = (bits >> i) & 1u;
            int a = size - 11 + i % 3, c = i / 3;
            bm_set(bm, size, a, c, b); bm_set(fn, size, a, c, true);
            bm_set(bm, size, c, a, b); bm_set(fn, size, c, a, true);
        }
    }
}

// ---------------------------------------------------------------------------
// Codeword placement and masking
// ---------------------------------------------------------------------------

static void draw_codewords(uint8_t* bm, const uint8_t* fn, int size,
                           const uint8_t* data, int data_len) {
    long i = 0;                                        // bit index
    long total_bits = (long)data_len * 8;
    for (int right = size - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;                     // skip the timing column
        for (int vert = 0; vert < size; vert++) {
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                bool upward = ((right + 1) & 2) == 0;
                int y = upward ? size - 1 - vert : vert;
                if (!bm_get(fn, x, y) && i < total_bits) {
                    bool b = (data[i >> 3] >> (7 - (i & 7))) & 1u;
                    bm_set(bm, size, x, y, b);
                    i++;
                }
            }
        }
    }
}

static bool mask_bit(int mask, int x, int y) {
    switch (mask) {
        case 0: return (x + y) % 2 == 0;
        case 1: return y % 2 == 0;
        case 2: return x % 3 == 0;
        case 3: return (x + y) % 3 == 0;
        case 4: return (x / 3 + y / 2) % 2 == 0;
        case 5: return (x * y) % 2 + (x * y) % 3 == 0;
        case 6: return ((x * y) % 2 + (x * y) % 3) % 2 == 0;
        default:return ((x + y) % 2 + (x * y) % 3) % 2 == 0;
    }
}

static void apply_mask(uint8_t* bm, const uint8_t* fn, int size, int mask) {
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (!bm_get(fn, x, y) && mask_bit(mask, x, y))
                bm_toggle(bm, x, y);
}

// ---- penalty rule 3 helpers (finder-like 1:1:3:1:1 patterns) --------------

static void fp_add_history(int run, int* hist, int size) {
    if (hist[0] == 0) run += size;                     // light border on entry
    memmove(&hist[1], &hist[0], 6 * sizeof(int));
    hist[0] = run;
}

static int fp_count_patterns(const int* hist, int size) {
    int n = hist[1];
    if (n <= 0 || n > size * 3) return 0;
    bool core = hist[2] == n && hist[3] == n * 3 && hist[4] == n && hist[5] == n;
    if (!core) return 0;
    return (hist[0] >= n * 4 && hist[6] >= n ? 1 : 0)
         + (hist[6] >= n * 4 && hist[0] >= n ? 1 : 0);
}

static int fp_terminate(bool run_color, int run_len, int* hist, int size) {
    if (run_color) { fp_add_history(run_len, hist, size); run_len = 0; }
    run_len += size;                                   // light border on exit
    fp_add_history(run_len, hist, size);
    return fp_count_patterns(hist, size);
}

static long penalty_score(const uint8_t* bm, int size) {
    long result = 0;

    // Rule 1: runs of five or more same-coloured modules in a line.
    // Rule 3 is evaluated in the same sweep.
    for (int y = 0; y < size; y++) {
        bool run_color = false;
        int run_len = 0;
        int hist[7] = { 0 };
        for (int x = 0; x < size; x++) {
            bool c = bm_get(bm, x, y);
            if (c == run_color) {
                run_len++;
                if (run_len == 5) result += QR_PENALTY_N1;
                else if (run_len > 5) result++;
            } else {
                fp_add_history(run_len, hist, size);
                if (!run_color) result += fp_count_patterns(hist, size) * QR_PENALTY_N3;
                run_color = c;
                run_len = 1;
            }
        }
        result += fp_terminate(run_color, run_len, hist, size) * QR_PENALTY_N3;
    }
    for (int x = 0; x < size; x++) {
        bool run_color = false;
        int run_len = 0;
        int hist[7] = { 0 };
        for (int y = 0; y < size; y++) {
            bool c = bm_get(bm, x, y);
            if (c == run_color) {
                run_len++;
                if (run_len == 5) result += QR_PENALTY_N1;
                else if (run_len > 5) result++;
            } else {
                fp_add_history(run_len, hist, size);
                if (!run_color) result += fp_count_patterns(hist, size) * QR_PENALTY_N3;
                run_color = c;
                run_len = 1;
            }
        }
        result += fp_terminate(run_color, run_len, hist, size) * QR_PENALTY_N3;
    }

    // Rule 2: 2x2 blocks of one colour.
    for (int y = 0; y < size - 1; y++) {
        for (int x = 0; x < size - 1; x++) {
            bool c = bm_get(bm, x, y);
            if (c == bm_get(bm, x + 1, y) && c == bm_get(bm, x, y + 1) &&
                c == bm_get(bm, x + 1, y + 1))
                result += QR_PENALTY_N2;
        }
    }

    // Rule 4: deviation of the dark-module ratio from 50 %.
    long dark = 0;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (bm_get(bm, x, y)) dark++;
    long total = (long)size * size;
    long diff = dark * 20 - total * 10;
    if (diff < 0) diff = -diff;
    long k = (diff + total - 1) / total - 1;
    result += k * QR_PENALTY_N4;
    return result;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

mw_err_t mw_qr_encode_version(const uint8_t* data, size_t len, mw_qr_ecc_t ecc,
                              uint8_t version, mw_qr_t* out) {
    if (!out) return MW_ERR_INVALID_ARG;
    if (!data && len) return MW_ERR_INVALID_ARG;
    if (ecc != MW_QR_ECC_L && ecc != MW_QR_ECC_M) return MW_ERR_INVALID_ARG;
    if (version < MW_QR_MIN_VERSION || version > MW_QR_MAX_VERSION)
        return MW_ERR_INVALID_ARG;
    if (len > mw_qr_byte_capacity(version, ecc)) return MW_ERR_TOO_MANY;

    const int size = 4 * version + 17;
    const int total_cw = qr_raw_data_modules(version) / 8;
    const int num_blocks = QR_NUM_BLOCKS[ecc][version];
    const int ecc_len = QR_ECC_PER_BLOCK[ecc][version];
    const int data_cw = total_cw - ecc_len * num_blocks;

    if (total_cw > QR_MAX_CODEWORDS || num_blocks > QR_MAX_BLOCKS ||
        ecc_len > QR_MAX_ECC_LEN) return MW_ERR_RANGE;   // table sanity

    // ---- 1. bit stream -----------------------------------------------------
    uint8_t cw[QR_MAX_CODEWORDS];
    memset(cw, 0, sizeof cw);
    long bit = 0;
    const int count_bits = (version <= 9) ? 8 : 16;

    #define PUT_BITS(value, n)                                                \
        do {                                                                  \
            for (int _i = (n) - 1; _i >= 0; _i--) {                           \
                if ((size_t)(bit >> 3) >= (size_t)data_cw) return MW_ERR_RANGE;\
                cw[bit >> 3] |= (uint8_t)((((uint32_t)(value) >> _i) & 1u)    \
                                          << (7 - (bit & 7)));                \
                bit++;                                                        \
            }                                                                 \
        } while (0)

    PUT_BITS(0x4u, 4);                       // byte mode
    PUT_BITS((uint32_t)len, count_bits);
    for (size_t i = 0; i < len; i++) PUT_BITS(data[i], 8);

    long capacity_bits = (long)data_cw * 8;
    long terminator = capacity_bits - bit;
    if (terminator > 4) terminator = 4;
    for (long i = 0; i < terminator; i++) PUT_BITS(0u, 1);
    while ((bit & 7) != 0) PUT_BITS(0u, 1);              // pad to a byte
    #undef PUT_BITS

    for (int i = (int)(bit >> 3), alt = 0; i < data_cw; i++, alt ^= 1)
        cw[i] = alt ? 0x11 : 0xEC;                       // pad codewords

    // ---- 2. Reed-Solomon, per block ---------------------------------------
    uint8_t divisor[QR_MAX_ECC_LEN];
    rs_divisor(ecc_len, divisor);

    uint8_t ecc_blocks[QR_MAX_BLOCKS][QR_MAX_ECC_LEN];
    const int short_blocks = num_blocks - total_cw % num_blocks;
    const int short_data   = data_cw / num_blocks;

    int offset = 0;
    for (int b = 0; b < num_blocks; b++) {
        int dlen = short_data + (b < short_blocks ? 0 : 1);
        rs_remainder(cw + offset, dlen, divisor, ecc_len, ecc_blocks[b]);
        offset += dlen;
    }

    // ---- 3. interleave -----------------------------------------------------
    uint8_t final_cw[QR_MAX_CODEWORDS];
    int o = 0;
    for (int i = 0; i <= short_data; i++) {
        int off = 0;
        for (int b = 0; b < num_blocks; b++) {
            int dlen = short_data + (b < short_blocks ? 0 : 1);
            if (i < dlen) final_cw[o++] = cw[off + i];
            off += dlen;
        }
    }
    for (int i = 0; i < ecc_len; i++)
        for (int b = 0; b < num_blocks; b++) final_cw[o++] = ecc_blocks[b][i];
    if (o != total_cw) return MW_ERR_RANGE;

    // ---- 4. matrix ---------------------------------------------------------
    uint8_t fn[MW_QR_MAX_SIZE * MW_QR_STRIDE];
    memset(out->modules, 0, sizeof out->modules);
    memset(fn, 0, sizeof fn);

    draw_function_patterns(out->modules, fn, size, version, ecc);
    draw_codewords(out->modules, fn, size, final_cw, total_cw);

    // ---- 5. mask selection -------------------------------------------------
    int best_mask = 0;
    long best_score = 0;
    for (int m = 0; m < 8; m++) {
        apply_mask(out->modules, fn, size, m);
        draw_format(out->modules, fn, size, ecc, m);
        long score = penalty_score(out->modules, size);
        if (m == 0 || score < best_score) { best_score = score; best_mask = m; }
        apply_mask(out->modules, fn, size, m);           // undo (XOR is its own inverse)
    }
    apply_mask(out->modules, fn, size, best_mask);
    draw_format(out->modules, fn, size, ecc, best_mask);

    out->version = version;
    out->size    = (uint8_t)size;
    out->mask    = (uint8_t)best_mask;
    out->ecc     = ecc;
    return MW_OK;
}

mw_err_t mw_qr_encode(const uint8_t* data, size_t len, mw_qr_ecc_t ecc,
                      mw_qr_t* out) {
    uint8_t v = mw_qr_min_version(len, ecc);
    if (v == 0) return MW_ERR_TOO_MANY;
    return mw_qr_encode_version(data, len, ecc, v, out);
}

mw_err_t mw_qr_encode_text(const char* text, mw_qr_ecc_t ecc, mw_qr_t* out) {
    if (!text) return MW_ERR_INVALID_ARG;
    size_t cap = mw_qr_byte_capacity(MW_QR_MAX_VERSION, ecc);
    size_t n = 0;
    while (n <= cap && text[n]) n++;
    if (n > cap) return MW_ERR_TOO_MANY;
    return mw_qr_encode((const uint8_t*)text, n, ecc, out);
}

// ---------------------------------------------------------------------------
// Shared with the scanner (camera_scan.cpp)
// ---------------------------------------------------------------------------

bool mw_qr_mask_bit(uint8_t mask, int x, int y) {
    return mask_bit(mask & 7, x, y);
}

bool mw_qr_bitmap_get(const uint8_t* bitmap, int x, int y) {
    if (!bitmap || x < 0 || y < 0 || x >= MW_QR_MAX_SIZE || y >= MW_QR_MAX_SIZE)
        return false;
    return bm_get(bitmap, x, y);
}

void mw_qr_bitmap_set(uint8_t* bitmap, int x, int y, bool dark) {
    if (!bitmap || x < 0 || y < 0 || x >= MW_QR_MAX_SIZE || y >= MW_QR_MAX_SIZE)
        return;
    bm_set(bitmap, MW_QR_MAX_SIZE, x, y, dark);
}

mw_err_t mw_qr_function_map(uint8_t version, uint8_t* out, size_t cap) {
    if (!out || cap < (size_t)MW_QR_MAX_SIZE * MW_QR_STRIDE)
        return MW_ERR_INVALID_ARG;
    if (version < MW_QR_MIN_VERSION || version > MW_QR_MAX_VERSION)
        return MW_ERR_INVALID_ARG;
    // draw_function_patterns() writes the modules into `bm` and the mask into
    // `fn`; the scanner only wants `fn`, so `bm` is a throwaway.
    static uint8_t scratch[MW_QR_MAX_SIZE * MW_QR_STRIDE];
    memset(scratch, 0, sizeof scratch);
    memset(out, 0, (size_t)MW_QR_MAX_SIZE * MW_QR_STRIDE);
    draw_function_patterns(scratch, out, 4 * version + 17, version, MW_QR_ECC_L);
    return MW_OK;
}

mw_err_t mw_qr_block_layout(uint8_t version, mw_qr_ecc_t ecc,
                            uint16_t* total_cw, uint16_t* data_cw,
                            uint8_t* num_blocks, uint8_t* ecc_len) {
    if (version < MW_QR_MIN_VERSION || version > MW_QR_MAX_VERSION)
        return MW_ERR_INVALID_ARG;
    if (ecc != MW_QR_ECC_L && ecc != MW_QR_ECC_M) return MW_ERR_INVALID_ARG;
    int total = qr_raw_data_modules(version) / 8;
    if (total_cw)   *total_cw = (uint16_t)total;
    if (data_cw)    *data_cw = (uint16_t)qr_data_codewords(version, ecc);
    if (num_blocks) *num_blocks = QR_NUM_BLOCKS[ecc][version];
    if (ecc_len)    *ecc_len = QR_ECC_PER_BLOCK[ecc][version];
    return MW_OK;
}
