// Camera capture -> QR decode plumbing (TZ 3.7).
//
// The frame grabber belongs to the HAL (mw_camera_capture, hal.h); this file
// turns an 8-bit grayscale frame into the string inside the QR symbol:
//
//   1. adaptive binarisation      - 8x8 block averages, so a screen photographed
//                                   under a desk lamp still thresholds cleanly;
//   2. finder-pattern detection   - the 1:1:3:1:1 run signature, horizontally
//                                   then confirmed vertically;
//   3. grid sampling              - an affine map built from the three finder
//                                   centres, majority-sampled per module;
//   4. symbol decoding            - format information (BCH, up to 3 bit errors),
//                                   unmasking, zig-zag codeword extraction,
//                                   de-interleaving, Reed-Solomon correction,
//                                   and the byte-mode segment parser.
//
// The tables and geometry come from qr_encode.c so the encoder and the decoder
// can never disagree about a version's layout.
//
// LIMITS, stated plainly:
//   * versions 1..20 (MW_QR_MAX_VERSION); larger symbols are refused. Animated
//     UR frames are ~100-200 characters, i.e. version 5 to 10.
//   * error-correction levels L and M. Q and H symbols are refused.
//   * byte mode only. Numeric/alphanumeric/kanji segments are refused.
//   * the module grid is sampled with an AFFINE transform from the three finder
//     centres. That is exact for a fronto-parallel view - which is the case
//     when the wallet is pointed at a phone or monitor - and degrades with
//     strong perspective. Alignment-pattern-based perspective correction is not
//     implemented.
//   * no multi-symbol (structured append) support.
//
// Unlike the USB files this one compiles and is exercised on the host: the
// encoder renders a symbol, the renderer turns it into a synthetic grayscale
// "photo", and the decoder has to read it back.
//
// SPDX-License-Identifier: MIT

// The host test runner links the C stubs in transfer_host_stubs.c instead;
// define MW_QR_SCAN_ON_HOST to compile the real decoder for a host harness.
#if !defined(MW_HOST_BUILD) || defined(MW_QR_SCAN_ON_HOST)

#include "qr_encode.h"
#include "../hal/hal.h"

#include <string.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// Large allocations
//
// The binarised frame (60 KB) and the block-average grid (7.5 KB) used to be
// statics. That is 67 KB of internal DRAM held for the whole life of the
// firmware to serve a screen the user is on for a few seconds, and the Arduino
// ESP32 core cannot move .bss to PSRAM - its sdkconfig leaves
// CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY unset, so EXT_RAM_BSS_ATTR
// expands to nothing. They are allocated from PSRAM on the first frame and
// released by mw_qr_scan_release(), which transfer.c calls when the scanner
// screen closes.
//
// PSRAM only, with no internal-RAM fallback: a 60 KB fallback would put the
// dram0_0_seg overflow straight back, and the firmware already refuses to boot
// without PSRAM (TZ 1.4). A failed allocation is reported as MW_ERR_MEMORY.
// ---------------------------------------------------------------------------
#if defined(__has_include)
#  if __has_include(<esp_heap_caps.h>)
#    define MW_SCAN_ESP_HEAP 1
#  endif
#endif
#ifndef MW_SCAN_ESP_HEAP
#  define MW_SCAN_ESP_HEAP 0
#endif
#if MW_SCAN_ESP_HEAP
#  include <esp_heap_caps.h>
#endif

namespace {

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

constexpr uint16_t MAX_W = 800;
constexpr uint16_t MAX_H = 600;
constexpr size_t   BIN_STRIDE = (MAX_W + 7) / 8;

constexpr int BLOCK = 8;                    // binariser block size
constexpr int MAX_BLOCKS_X = MAX_W / BLOCK;
constexpr int MAX_BLOCKS_Y = MAX_H / BLOCK;

constexpr int MAX_FINDERS = 48;

constexpr size_t BIN_BYTES    = BIN_STRIDE * (size_t)MAX_H;          // 60000
constexpr size_t BLOCKS_BYTES = (size_t)MAX_BLOCKS_Y * MAX_BLOCKS_X; //  7500
constexpr size_t SCAN_ARENA_BYTES = BIN_BYTES + BLOCKS_BYTES;

struct Binary {
    uint8_t* bits;          // BIN_BYTES, in the PSRAM arena
    uint16_t w, h;
};

// One working set: the scanner runs on one task and a 60 KB frame does not
// belong on a FreeRTOS stack. `bits` and g_blocks are views into one PSRAM
// allocation and are NULL until scan_arena_alloc() has run.
uint8_t* g_scan_arena = NULL;
Binary   g_bin        = { NULL, 0, 0 };
uint8_t  (*g_blocks)[MAX_BLOCKS_X] = NULL;

inline bool bin_get(const Binary& b, int x, int y) {
    if (!b.bits) return false;
    if (x < 0 || y < 0 || x >= b.w || y >= b.h) return false;
    return (b.bits[(size_t)y * BIN_STRIDE + (size_t)(x >> 3)] >> (x & 7)) & 1u;
}

inline void bin_set(Binary& b, int x, int y, bool dark) {
    if (!b.bits) return;
    size_t i = (size_t)y * BIN_STRIDE + (size_t)(x >> 3);
    uint8_t m = (uint8_t)(1u << (x & 7));
    if (dark) b.bits[i] |= m; else b.bits[i] &= (uint8_t)~m;
}

void scan_arena_free(void) {
    if (!g_scan_arena) return;
    free(g_scan_arena);
    g_scan_arena = NULL;
    g_bin.bits   = NULL;
    g_bin.w      = 0;
    g_bin.h      = 0;
    g_blocks     = NULL;
}

// Allocates and zeroes the working set. The zeroing replaces the BSS
// initialisation the two buffers used to get for free: binarise() writes every
// pixel of the *current* frame, but the finder search reads up to MAX_W/MAX_H.
bool scan_arena_alloc(void) {
    if (g_scan_arena) return true;
#if MW_SCAN_ESP_HEAP
    g_scan_arena = (uint8_t*)heap_caps_malloc(SCAN_ARENA_BYTES,
                                              MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#else
    g_scan_arena = (uint8_t*)malloc(SCAN_ARENA_BYTES);   // non-ESP host harness
#endif
    if (!g_scan_arena) return false;
    memset(g_scan_arena, 0, SCAN_ARENA_BYTES);
    g_bin.bits = g_scan_arena;
    g_blocks   = (uint8_t (*)[MAX_BLOCKS_X])(g_scan_arena + BIN_BYTES);
    return true;
}

// ---------------------------------------------------------------------------
// 1. Adaptive binarisation
//
// Global thresholding fails on a photograph of a screen: the backlight falls
// off towards the edges and one corner ends up entirely "dark". Averaging in
// 8x8 blocks and thresholding each pixel against the mean of the surrounding
// 5x5 block neighbourhood tracks that gradient.
// ---------------------------------------------------------------------------

void binarise(const uint8_t* gray, uint16_t w, uint16_t h) {
    if (!g_bin.bits || !g_blocks) return;
    g_bin.w = w;
    g_bin.h = h;

    const int bx_count = (w + BLOCK - 1) / BLOCK;
    const int by_count = (h + BLOCK - 1) / BLOCK;

    for (int by = 0; by < by_count; by++) {
        for (int bx = 0; bx < bx_count; bx++) {
            uint32_t sum = 0;
            uint32_t n = 0;
            int y0 = by * BLOCK, x0 = bx * BLOCK;
            for (int y = y0; y < y0 + BLOCK && y < h; y++)
                for (int x = x0; x < x0 + BLOCK && x < w; x++) {
                    sum += gray[(size_t)y * w + (size_t)x];
                    n++;
                }
            g_blocks[by][bx] = (uint8_t)(n ? sum / n : 128);
        }
    }

    for (int by = 0; by < by_count; by++) {
        for (int bx = 0; bx < bx_count; bx++) {
            // Mean of the 5x5 block neighbourhood, clamped to the image.
            uint32_t sum = 0, n = 0;
            for (int dy = -2; dy <= 2; dy++) {
                int yy = by + dy;
                if (yy < 0 || yy >= by_count) continue;
                for (int dx = -2; dx <= 2; dx++) {
                    int xx = bx + dx;
                    if (xx < 0 || xx >= bx_count) continue;
                    sum += g_blocks[yy][xx];
                    n++;
                }
            }
            // Bias the threshold slightly towards "light" so thin dark modules
            // survive; 1/32 is the same nudge ZXing's hybrid binariser uses.
            int thr = (int)(sum / (n ? n : 1));
            thr -= thr / 32;

            int y0 = by * BLOCK, x0 = bx * BLOCK;
            for (int y = y0; y < y0 + BLOCK && y < h; y++)
                for (int x = x0; x < x0 + BLOCK && x < w; x++)
                    bin_set(g_bin, x, y, gray[(size_t)y * w + (size_t)x] < thr);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Finder patterns
// ---------------------------------------------------------------------------

struct Finder {
    float x, y;
    float module;
    int   count;
};

Finder g_finders[MAX_FINDERS];
int    g_finder_count;

// True when five consecutive runs match the 1:1:3:1:1 signature of a finder
// pattern, allowing each run to be off by half a module.
bool ratio_ok(const int run[5]) {
    int total = run[0] + run[1] + run[2] + run[3] + run[4];
    if (total < 7) return false;
    int module_x2 = (total * 2) / 7;            // module size, doubled
    if (module_x2 == 0) return false;
    int tol = module_x2 / 2 + 1;                // +- half a module
    return abs(module_x2 - run[0] * 2) < tol
        && abs(module_x2 - run[1] * 2) < tol
        && abs(3 * module_x2 - run[2] * 2) < 3 * tol
        && abs(module_x2 - run[3] * 2) < tol
        && abs(module_x2 - run[4] * 2) < tol;
}

float run_centre(int end, const int run[5]) {
    return (float)end - (float)run[4] - (float)run[3] - (float)run[2] / 2.0f;
}

// Walks a column through (x, y) and returns the vertical centre of the finder
// pattern there, or -1 if the column does not match.
float vertical_check(int x, int y, int horizontal_total) {
    const int max_count = horizontal_total * 2 / 3 + 1;
    int run[5] = { 0, 0, 0, 0, 0 };
    int i = y;
    while (i >= 0 && bin_get(g_bin, x, i)) { run[2]++; i--; }
    if (i < 0) return -1;
    while (i >= 0 && !bin_get(g_bin, x, i) && run[1] < max_count) { run[1]++; i--; }
    if (i < 0 || run[1] >= max_count) return -1;
    while (i >= 0 && bin_get(g_bin, x, i) && run[0] < max_count) { run[0]++; i--; }
    if (run[0] >= max_count) return -1;

    i = y + 1;
    while (i < g_bin.h && bin_get(g_bin, x, i)) { run[2]++; i++; }
    if (i >= g_bin.h) return -1;
    while (i < g_bin.h && !bin_get(g_bin, x, i) && run[3] < max_count) { run[3]++; i++; }
    if (i >= g_bin.h || run[3] >= max_count) return -1;
    while (i < g_bin.h && bin_get(g_bin, x, i) && run[4] < max_count) { run[4]++; i++; }
    if (run[4] >= max_count) return -1;

    int total = run[0] + run[1] + run[2] + run[3] + run[4];
    // The vertical cross section must be about as thick as the horizontal one.
    if (5 * abs(total - horizontal_total) >= 2 * horizontal_total) return -1;
    if (!ratio_ok(run)) return -1;
    return run_centre(i, run);
}

void add_finder(float x, float y, float module) {
    for (int i = 0; i < g_finder_count; i++) {
        Finder& f = g_finders[i];
        float dx = f.x - x, dy = f.y - y;
        if (dx * dx + dy * dy < module * module * 4.0f) {
            // Same pattern seen again: average it in, which sharpens the centre.
            float n = (float)f.count;
            f.x = (f.x * n + x) / (n + 1);
            f.y = (f.y * n + y) / (n + 1);
            f.module = (f.module * n + module) / (n + 1);
            f.count++;
            return;
        }
    }
    if (g_finder_count < MAX_FINDERS) {
        g_finders[g_finder_count++] = { x, y, module, 1 };
        return;
    }
    // Full: evict the weakest candidate rather than dropping this one. A real
    // finder pattern near the bottom of the frame is scanned last, so simply
    // ignoring late candidates loses the bottom-left corner of big symbols.
    int worst = 0;
    for (int i = 1; i < MAX_FINDERS; i++)
        if (g_finders[i].count < g_finders[worst].count) worst = i;
    if (g_finders[worst].count <= 1) g_finders[worst] = { x, y, module, 1 };
}

void find_finders(void) {
    g_finder_count = 0;

    // The run state machine alternates dark/light/dark/light/dark, which is the
    // 1:1:3:1:1 cross section of a finder pattern. `state` is the index of the
    // run being counted; even states are dark, odd states light.
    for (int y = 0; y < g_bin.h; y += 2) {
        int run[5] = { 0, 0, 0, 0, 0 };
        int state = 0;
        for (int x = 0; x < g_bin.w; x++) {
            if (bin_get(g_bin, x, y)) {              // dark
                if (state & 1) state++;              // was counting light
                run[state]++;
            } else {                                 // light
                if ((state & 1) == 0) {              // was counting dark
                    if (state == 4) {
                        if (ratio_ok(run)) {
                            int total = run[0] + run[1] + run[2] + run[3] + run[4];
                            float cx = run_centre(x, run);
                            float module = (float)total / 7.0f;
                            float cy = vertical_check((int)(cx + 0.5f), y, total);
                            if (cy >= 0) add_finder(cx, cy, module);
                        }
                        // Slide the window: the trailing dark run may be the
                        // leading run of the next pattern.
                        run[0] = run[2]; run[1] = run[3]; run[2] = run[4];
                        run[3] = 1; run[4] = 0;
                        state = 3;
                    } else {
                        state++;
                        run[state]++;
                    }
                } else {
                    run[state]++;
                }
            }
        }
        // A pattern flush against the right edge still counts.
        if (state == 4 && ratio_ok(run)) {
            int total = run[0] + run[1] + run[2] + run[3] + run[4];
            float cx = run_centre(g_bin.w, run);
            float cy = vertical_check((int)(cx + 0.5f), y, total);
            if (cy >= 0) add_finder(cx, cy, (float)total / 7.0f);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Grid sampling
// ---------------------------------------------------------------------------

struct Grid {
    uint8_t modules[MW_QR_MAX_SIZE * MW_QR_STRIDE];
    int     size;
    int     version;
};

float dist(const Finder& a, const Finder& b) {
    float dx = a.x - b.x, dy = a.y - b.y;
    // No libm: a Newton iteration on the square root is plenty and keeps the
    // firmware free of the soft-float library.
    float s = dx * dx + dy * dy;
    if (s <= 0) return 0;
    float r = s;
    for (int i = 0; i < 20; i++) r = 0.5f * (r + s / r);
    return r;
}

// Chooses the three candidates that actually look like a QR symbol's corners -
// two legs of equal length meeting at a right angle, with consistent module
// sizes - and labels them top-left, top-right and bottom-left.
//
// Picking the three highest-scoring candidates is not enough: dense data areas
// throw off plenty of 1:1:3:1:1 cross sections, and one of them can easily
// outscore a real corner. Scoring whole triples is what rejects them.
bool order_finders(const Finder* in, int n, Finder* tl, Finder* tr, Finder* bl) {
    if (n < 3) return false;

    // Consider at most the twelve best-confirmed candidates; C(12,3) = 220
    // triples is nothing, and a real corner is always well confirmed.
    constexpr int MAX_CAND = 12;
    int cand[MAX_CAND];
    int ncand = 0;
    for (int i = 0; i < n; i++) {
        if (ncand < MAX_CAND) { cand[ncand++] = i; continue; }
        int worst = 0;
        for (int k = 1; k < ncand; k++)
            if (in[cand[k]].count < in[cand[worst]].count) worst = k;
        if (in[i].count > in[cand[worst]].count) cand[worst] = i;
    }
    if (ncand < 3) return false;

    float best_score = 1e30f;
    int   best[3] = { -1, -1, -1 };

    for (int a = 0; a < ncand; a++) {
        for (int b = a + 1; b < ncand; b++) {
            for (int c = b + 1; c < ncand; c++) {
                const Finder& A = in[cand[a]];
                const Finder& B = in[cand[b]];
                const Finder& C = in[cand[c]];

                // Module sizes must agree; the three finder patterns of one
                // symbol are the same size by construction.
                float mmin = A.module, mmax = A.module;
                if (B.module < mmin) mmin = B.module;
                if (B.module > mmax) mmax = B.module;
                if (C.module < mmin) mmin = C.module;
                if (C.module > mmax) mmax = C.module;
                if (mmin <= 0.0f || mmax > mmin * 1.5f) continue;

                float ab = dist(A, B), ac = dist(A, C), bc = dist(B, C);
                // The longest side is the hypotenuse; the other two are legs.
                float hyp, l1, l2;
                if (bc >= ab && bc >= ac)      { hyp = bc; l1 = ab; l2 = ac; }
                else if (ac >= ab && ac >= bc) { hyp = ac; l1 = ab; l2 = bc; }
                else                           { hyp = ab; l1 = ac; l2 = bc; }
                if (l1 <= 0.0f || l2 <= 0.0f) continue;

                // Legs equal, hypotenuse sqrt(2) times a leg.
                float leg_err = (l1 > l2) ? (l1 / l2 - 1.0f) : (l2 / l1 - 1.0f);
                float mean_leg = (l1 + l2) / 2.0f;
                float hyp_err  = hyp / (mean_leg * 1.41421356f) - 1.0f;
                if (hyp_err < 0) hyp_err = -hyp_err;
                if (leg_err > 0.25f || hyp_err > 0.15f) continue;

                // Prefer the largest well-formed triple: a symbol's corners are
                // further apart than any accidental pattern inside it.
                float score = leg_err + hyp_err + (mmax / mmin - 1.0f)
                            - mean_leg * 0.0005f;
                if (score < best_score) {
                    best_score = score;
                    best[0] = cand[a]; best[1] = cand[b]; best[2] = cand[c];
                }
            }
        }
    }
    if (best[0] < 0) return false;

    Finder a = in[best[0]], b = in[best[1]], c = in[best[2]];

    // The two furthest apart are the top-right and bottom-left corners; the
    // remaining one is the top-left, at the right angle of the triangle.
    float ab = dist(a, b), ac = dist(a, c), bc = dist(b, c);
    Finder corner, p, q;
    if (bc >= ab && bc >= ac)      { corner = a; p = b; q = c; }
    else if (ac >= ab && ac >= bc) { corner = b; p = a; q = c; }
    else                           { corner = c; p = a; q = b; }

    // Handedness. In image coordinates (y downwards) the cross product of
    // (top-right - top-left) with (bottom-left - top-left) is positive, so a
    // positive cross means `p` is the top-right corner.
    float cross = (p.x - corner.x) * (q.y - corner.y)
                - (p.y - corner.y) * (q.x - corner.x);
    *tl = corner;
    if (cross > 0) { *tr = p; *bl = q; } else { *tr = q; *bl = p; }
    return true;
}

// Majority over a neighbourhood, so a single speckle cannot flip a module.
// The kernel has to stay inside one module: at three pixels per module a 3x3
// window already reaches into the neighbours, which turns a clean symbol into
// an uncorrectable one.
bool sample_module(float px, float py, float module) {
    int x = (int)(px + 0.5f), y = (int)(py + 0.5f);
    if (module < 4.0f) return bin_get(g_bin, x, y);
    int dark = 0;
    for (int dy = -1; dy <= 1; dy++)
        for (int dx = -1; dx <= 1; dx++)
            if (bin_get(g_bin, x + dx, y + dy)) dark++;
    return dark >= 5;
}

// Maps module coordinates to image coordinates for a candidate dimension. The
// three finder centres sit at module (3.5, 3.5), (dim - 3.5, 3.5) and
// (3.5, dim - 3.5), which fixes an affine basis.
struct Basis {
    float ox, oy;          // image position of module coordinate (3.5, 3.5)
    float exx, exy;        // one module step along +x
    float eyx, eyy;        // one module step along +y
    float module;          // pixels per module
};

Basis make_basis(const Finder& tl, const Finder& tr, const Finder& bl, int dim) {
    Basis b;
    float span = (float)dim - 7.0f;
    b.ox = tl.x; b.oy = tl.y;
    b.exx = (tr.x - tl.x) / span; b.exy = (tr.y - tl.y) / span;
    b.eyx = (bl.x - tl.x) / span; b.eyy = (bl.y - tl.y) / span;
    float mx = b.exx * b.exx + b.exy * b.exy;
    float my = b.eyx * b.eyx + b.eyy * b.eyy;
    float s = (mx + my) / 2.0f;
    float r = s > 0 ? s : 1.0f;
    for (int i = 0; i < 20; i++) r = 0.5f * (r + s / r);   // sqrt, no libm
    b.module = r;
    return b;
}

inline void basis_map(const Basis& b, int i, int j, float* px, float* py) {
    float u = (float)i + 0.5f - 3.5f;
    float v = (float)j + 0.5f - 3.5f;
    *px = b.ox + u * b.exx + v * b.eyx;
    *py = b.oy + u * b.exy + v * b.eyy;
}

// Fraction of the timing-pattern modules that alternate as they must. This is
// what pins the version down: the module size measured from a finder pattern is
// biased under rotation (a horizontal cut through a tilted square is longer
// than the square's side), so the dimension estimate derived from it can be off
// by a whole version. The timing pattern is unambiguous.
float timing_score(const Basis& b, int dim) {
    int good = 0, total = 0;
    for (int i = 8; i <= dim - 9; i++) {
        float px, py;
        bool want = (i % 2 == 0);
        basis_map(b, i, 6, &px, &py);
        if (sample_module(px, py, b.module) == want) good++;
        total++;
        basis_map(b, 6, i, &px, &py);
        if (sample_module(px, py, b.module) == want) good++;
        total++;
    }
    return total ? (float)good / (float)total : 0.0f;
}

bool build_grid(const Finder& tl, const Finder& tr, const Finder& bl, Grid* g) {
    float module = (tl.module + tr.module + bl.module) / 3.0f;
    if (module < 1.0f) return false;

    float across = dist(tl, tr) / module;
    float down   = dist(tl, bl) / module;
    int estimate = (int)((across + down) / 2.0f + 0.5f) + 7;

    // Search dimensions outwards from the estimate, scoring each by its timing
    // pattern. Dimensions are always 4 * version + 17, i.e. 1 mod 4.
    int best_dim = 0;
    float best_score = 0.0f;
    Basis best_basis = { 0, 0, 0, 0, 0, 0, 0 };

    for (int step = 0; step <= 12; step++) {
        for (int sign = (step == 0 ? 0 : -1); sign <= 1; sign += 2) {
            int dim = estimate + sign * step * 4;
            dim -= (dim - 21) % 4;                   // snap to 4k + 21
            if (dim < 21 || dim > MW_QR_MAX_SIZE) continue;
            Basis b = make_basis(tl, tr, bl, dim);
            if (b.module < 1.0f) continue;
            float score = timing_score(b, dim);
            if (score > best_score + 0.001f) {
                best_score = score;
                best_dim = dim;
                best_basis = b;
            }
            if (sign == 0) break;
        }
        // A perfect timing pattern cannot be improved on.
        if (best_score >= 0.999f) break;
    }

    // Below this the "symbol" is noise, not a QR code.
    if (best_dim == 0 || best_score < 0.8f) return false;

    g->size = best_dim;
    g->version = (best_dim - 17) / 4;
    memset(g->modules, 0, sizeof g->modules);

    for (int j = 0; j < best_dim; j++) {
        for (int i = 0; i < best_dim; i++) {
            float px, py;
            basis_map(best_basis, i, j, &px, &py);
            if (sample_module(px, py, best_basis.module))
                mw_qr_bitmap_set(g->modules, i, j, true);
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// 4. Symbol decoding
// ---------------------------------------------------------------------------

// GF(2^8) with the QR primitive polynomial 0x11D.
uint8_t gf_exp[512];
uint8_t gf_log[256];
bool    gf_ready = false;

void gf_init(void) {
    if (gf_ready) return;
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    for (int i = 255; i < 512; i++) gf_exp[i] = gf_exp[i - 255];
    gf_log[0] = 0;
    gf_ready = true;
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    if (!a || !b) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

inline uint8_t ginv(uint8_t a) {
    return gf_exp[255 - gf_log[a]];
}

// Reed-Solomon decode in place: syndromes, Berlekamp-Massey, Chien search and
// Forney. Returns false when the block has more errors than it can carry.
bool rs_correct(uint8_t* data, int len, int ecc_len) {
    gf_init();
    if (ecc_len <= 0 || len <= ecc_len || len > 255) return false;

    // Syndromes S_i = r(alpha^i), i = 0 .. ecc_len-1.
    uint8_t synd[64];
    bool all_zero = true;
    for (int i = 0; i < ecc_len; i++) {
        uint8_t s = 0;
        for (int j = 0; j < len; j++) s = (uint8_t)(gmul(s, gf_exp[i]) ^ data[j]);
        synd[i] = s;
        if (s) all_zero = false;
    }
    if (all_zero) return true;

    // Berlekamp-Massey.
    uint8_t lambda[65] = { 1 }, prev[65] = { 1 }, tmp[65];
    int l = 0, m = 1;
    uint8_t b = 1;
    for (int n = 0; n < ecc_len; n++) {
        uint8_t d = synd[n];
        for (int i = 1; i <= l; i++) d ^= gmul(lambda[i], synd[n - i]);
        if (d == 0) {
            m++;
        } else if (2 * l <= n) {
            memcpy(tmp, lambda, sizeof tmp);
            uint8_t scale = gmul(d, ginv(b));
            for (int i = 0; i + m <= ecc_len; i++)
                lambda[i + m] ^= gmul(scale, prev[i]);
            l = n + 1 - l;
            memcpy(prev, tmp, sizeof tmp);
            b = d;
            m = 1;
        } else {
            uint8_t scale = gmul(d, ginv(b));
            for (int i = 0; i + m <= ecc_len; i++)
                lambda[i + m] ^= gmul(scale, prev[i]);
            m++;
        }
    }
    if (l <= 0 || l > ecc_len / 2) return false;

    // Chien search: roots of lambda give the error positions.
    int pos[32];
    int nerr = 0;
    for (int i = 0; i < len; i++) {
        // Evaluate lambda at alpha^-(i) ... expressed as alpha^(255 - i).
        uint8_t v = 0;
        for (int k = 0; k <= l; k++)
            v ^= gmul(lambda[k], gf_exp[(255 - ((i * k) % 255)) % 255]);
        if (v == 0) {
            if (nerr >= (int)(sizeof pos / sizeof pos[0])) return false;
            pos[nerr++] = len - 1 - i;
        }
    }
    if (nerr != l) return false;

    // Omega = S(x) * lambda(x) mod x^ecc_len.
    uint8_t omega[65];
    memset(omega, 0, sizeof omega);
    for (int i = 0; i < ecc_len; i++) {
        uint8_t acc = 0;
        for (int k = 0; k <= i && k <= l; k++) acc ^= gmul(synd[i - k], lambda[k]);
        omega[i] = acc;
    }

    // Forney.
    for (int e = 0; e < nerr; e++) {
        int p = pos[e];
        if (p < 0 || p >= len) return false;
        int xi = (len - 1 - p) % 255;
        uint8_t xinv = gf_exp[(255 - xi) % 255];

        uint8_t num = 0, xp = 1;
        for (int i = 0; i < ecc_len; i++) { num ^= gmul(omega[i], xp); xp = gmul(xp, xinv); }

        // lambda'(x) keeps only the odd powers over GF(2).
        uint8_t den = 0;
        xp = 1;
        for (int i = 1; i <= l; i += 2) {
            den ^= gmul(lambda[i], xp);
            xp = gmul(xp, gmul(xinv, xinv));
        }
        if (den == 0) return false;
        data[p] ^= gmul(num, ginv(den));
    }

    // Re-check: a false root set can produce a block that still fails.
    for (int i = 0; i < ecc_len; i++) {
        uint8_t s = 0;
        for (int j = 0; j < len; j++) s = (uint8_t)(gmul(s, gf_exp[i]) ^ data[j]);
        if (s) return false;
    }
    return true;
}

// Format information: 15 bits, BCH(15,5) with generator 0x537 masked by 0x5412.
// All 32 valid words are regenerated and the closest one within 3 bit errors
// wins, which is exactly what the standard specifies.
bool decode_format(uint32_t bits, uint8_t* ecc_out, uint8_t* mask_out) {
    int best = -1, best_dist = 4;
    for (int data = 0; data < 32; data++) {
        uint32_t rem = (uint32_t)data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537u);
        uint32_t word = (((uint32_t)data << 10) | rem) ^ 0x5412u;
        uint32_t diff = word ^ bits;
        int d = 0;
        while (diff) { d += (int)(diff & 1u); diff >>= 1; }
        if (d < best_dist) { best_dist = d; best = data; }
        else if (d == best_dist) best = -1;          // ambiguous
    }
    if (best < 0) return false;
    // Format ECC bits: 01 = L, 00 = M, 11 = Q, 10 = H.
    switch ((best >> 3) & 3) {
        case 1: *ecc_out = MW_QR_ECC_L; break;
        case 0: *ecc_out = MW_QR_ECC_M; break;
        default: return false;                        // Q and H unsupported
    }
    *mask_out = (uint8_t)(best & 7);
    return true;
}

uint32_t read_format_copy1(const Grid* g) {
    uint32_t bits = 0;
    for (int i = 0; i <= 5; i++)
        bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 8, i) << i;
    bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 8, 7) << 6;
    bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 8, 8) << 7;
    bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 7, 8) << 8;
    for (int i = 9; i < 15; i++)
        bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 14 - i, 8) << i;
    return bits;
}

uint32_t read_format_copy2(const Grid* g) {
    uint32_t bits = 0;
    for (int i = 0; i < 8; i++)
        bits |= (uint32_t)mw_qr_bitmap_get(g->modules, g->size - 1 - i, 8) << i;
    for (int i = 8; i < 15; i++)
        bits |= (uint32_t)mw_qr_bitmap_get(g->modules, 8, g->size - 15 + i) << i;
    return bits;
}

// Codewords, in the zig-zag order of clause 7.7.3, skipping function modules.
int read_codewords(const Grid* g, const uint8_t* fn, uint8_t mask,
                   uint8_t* out, int out_cap) {
    int n = 0;
    int bit = 0;
    uint8_t acc = 0;
    for (int right = g->size - 1; right >= 1; right -= 2) {
        if (right == 6) right = 5;
        for (int vert = 0; vert < g->size; vert++) {
            for (int j = 0; j < 2; j++) {
                int x = right - j;
                bool upward = ((right + 1) & 2) == 0;
                int y = upward ? g->size - 1 - vert : vert;
                if (mw_qr_bitmap_get(fn, x, y)) continue;
                bool b = mw_qr_bitmap_get(g->modules, x, y);
                if (mw_qr_mask_bit(mask, x, y)) b = !b;
                acc = (uint8_t)((acc << 1) | (b ? 1 : 0));
                if (++bit == 8) {
                    if (n >= out_cap) return n;
                    out[n++] = acc;
                    acc = 0;
                    bit = 0;
                }
            }
        }
    }
    return n;
}

// Undoes the block interleaving of clause 7.6 and error-corrects each block.
int deinterleave_and_correct(const uint8_t* cw, int total_cw, int data_cw,
                             int num_blocks, int ecc_len, uint8_t* out,
                             int out_cap) {
    if (num_blocks <= 0 || num_blocks > 32) return -1;
    if (data_cw > out_cap) return -1;

    const int short_blocks = num_blocks - total_cw % num_blocks;
    const int short_data   = data_cw / num_blocks;

    uint8_t block[32][256];
    int     block_len[32];
    for (int b = 0; b < num_blocks; b++)
        block_len[b] = short_data + (b < short_blocks ? 0 : 1);

    int o = 0;
    for (int i = 0; i <= short_data; i++)
        for (int b = 0; b < num_blocks; b++)
            if (i < block_len[b]) {
                if (o >= total_cw) return -1;
                block[b][i] = cw[o++];
            }
    for (int i = 0; i < ecc_len; i++)
        for (int b = 0; b < num_blocks; b++) {
            if (o >= total_cw) return -1;
            block[b][block_len[b] + i] = cw[o++];
        }

    int n = 0;
    for (int b = 0; b < num_blocks; b++) {
        if (!rs_correct(block[b], block_len[b] + ecc_len, ecc_len)) return -1;
        for (int i = 0; i < block_len[b]; i++) {
            if (n >= out_cap) return -1;
            out[n++] = block[b][i];
        }
    }
    return n;
}

// Byte-mode segment parser. Other modes are refused rather than mis-decoded.
int parse_segments(const uint8_t* data, int data_len, int version,
                   char* out, size_t out_cap) {
    int bitpos = 0;
    const int total_bits = data_len * 8;
    size_t o = 0;

    auto take = [&](int n) -> int {
        if (bitpos + n > total_bits) return -1;
        int v = 0;
        for (int i = 0; i < n; i++) {
            int b = (data[(bitpos + i) >> 3] >> (7 - ((bitpos + i) & 7))) & 1;
            v = (v << 1) | b;
        }
        bitpos += n;
        return v;
    };

    for (;;) {
        if (bitpos + 4 > total_bits) break;
        int mode = take(4);
        if (mode <= 0) break;                       // 0000 = terminator
        if (mode != 4) return -1;                   // byte mode only
        int count_bits = (version <= 9) ? 8 : 16;
        int count = take(count_bits);
        if (count < 0) return -1;
        if (bitpos + count * 8 > total_bits) return -1;
        for (int i = 0; i < count; i++) {
            int c = take(8);
            if (c < 0) return -1;
            if (o + 1 >= out_cap) return -1;
            out[o++] = (char)c;
        }
    }
    if (o == 0) return -1;
    out[o] = '\0';
    return (int)o;
}

Grid    g_grid;
uint8_t g_fn[MW_QR_MAX_SIZE * MW_QR_STRIDE];

} // namespace

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

extern "C" mw_err_t mw_qr_scan_frame(const uint8_t* gray, uint16_t width,
                                     uint16_t height, char* out, size_t out_cap) {
    if (!gray || !out || out_cap < 2) return MW_ERR_INVALID_ARG;
    if (width < 32 || height < 32 || width > MAX_W || height > MAX_H)
        return MW_ERR_RANGE;
    // First frame of a scan session: take the working set from PSRAM.
    if (!scan_arena_alloc()) return MW_ERR_MEMORY;

    binarise(gray, width, height);
    find_finders();

    Finder tl, tr, bl;
    if (!order_finders(g_finders, g_finder_count, &tl, &tr, &bl))
        return MW_ERR_FORMAT;
    if (!build_grid(tl, tr, bl, &g_grid)) return MW_ERR_FORMAT;
    if (g_grid.version < MW_QR_MIN_VERSION || g_grid.version > MW_QR_MAX_VERSION)
        return MW_ERR_NOT_SUPPORTED;

    uint8_t ecc = 0, mask = 0;
    if (!decode_format(read_format_copy1(&g_grid), &ecc, &mask) &&
        !decode_format(read_format_copy2(&g_grid), &ecc, &mask))
        return MW_ERR_FORMAT;

    if (mw_qr_function_map((uint8_t)g_grid.version, g_fn, sizeof g_fn) != MW_OK)
        return MW_ERR_FORMAT;

    uint16_t total_cw = 0, data_cw = 0;
    uint8_t num_blocks = 0, ecc_len = 0;
    if (mw_qr_block_layout((uint8_t)g_grid.version, (mw_qr_ecc_t)ecc,
                           &total_cw, &data_cw, &num_blocks, &ecc_len) != MW_OK)
        return MW_ERR_FORMAT;

    static uint8_t cw[1200];
    int n = read_codewords(&g_grid, g_fn, mask, cw, (int)sizeof cw);
    if (n < total_cw) return MW_ERR_FORMAT;

    static uint8_t data[1200];
    int dn = deinterleave_and_correct(cw, total_cw, data_cw, num_blocks, ecc_len,
                                      data, (int)sizeof data);
    if (dn < 0) return MW_ERR_CHECKSUM;

    int len = parse_segments(data, dn, g_grid.version, out, out_cap);
    if (len <= 0) return MW_ERR_FORMAT;
    return MW_OK;
}

extern "C" mw_err_t mw_qr_scan_once(char* out, size_t out_cap) {
    if (!out || out_cap < 2) return MW_ERR_INVALID_ARG;
    mw_camera_frame_t frame;
    memset(&frame, 0, sizeof frame);
    mw_err_t err = mw_camera_capture(&frame);
    if (err != MW_OK) return err;
    if (!frame.data || frame.width == 0 || frame.height == 0) return MW_ERR_IO;
    return mw_qr_scan_frame(frame.data, frame.width, frame.height, out, out_cap);
}

// Releases the 67 KB working set. Called by transfer.c when the scanner screen
// closes; calling it between frames would only make the next frame re-allocate.
extern "C" void mw_qr_scan_release(void) {
    scan_arena_free();
}

#endif /* !MW_HOST_BUILD || MW_QR_SCAN_ON_HOST */
