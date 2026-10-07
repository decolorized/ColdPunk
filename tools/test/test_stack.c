// Stack budget of the crypto task (bug 4: the device reset in CLSAG because
// signing needed more than the 32 KiB task stack).
//
// Each operation the shell runs on the crypto task is measured with the
// paint method: a noinline helper fills a large region below the caller's
// frame with a pattern, the operation runs over that region, and the deepest
// byte that no longer holds the pattern gives the peak stack use.
//
// Cases:
//   * the device's transaction: 1 input (ring 16), recipient + change, view
//     tags, fee 30660000, 44-byte extra with an encrypted payment id, key
//     image known from an earlier export;
//   * 2 inputs, 2 outputs;
//   * 1 input, 16 outputs (15 recipients + change);
//   * outputs -> key images, wallet open.
//
// Budget: MW_CRYPTO_TASK_STACK minus 4 KiB for the shell frames above the
// operation and 8 KiB for the device-only costs (Xtensa frame overhead,
// interrupt frame, TLS) = 20 KiB. The figures are printed in every run; the
// assertion is skipped under AddressSanitizer, whose redzones inflate frames.
#include <stdio.h>
#include <string.h>

#include "test_framework.h"
#include "fx_feather.h"

#include "config/app_config.h"
#include "crypto/memzero.h"
#include "crypto/random.h"
#include "monero/address.h"
#include "monero/mnemonic.h"
#include "wallet/file_store.h"
#include "wallet/ki_cache.h"
#include "wallet/secure_storage.h"
#include "wallet/wallet_ops.h"
#include "wallet/wallet_store.h"

void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);

#define STORE_DIR    "./.mw_test_stack"
#define STACK_BUDGET (MW_CRYPTO_TASK_STACK - 4096 - 8192)

#if defined(__SANITIZE_ADDRESS__)
#define MEASURE_ASSERT 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MEASURE_ASSERT 0
#endif
#endif
#ifndef MEASURE_ASSERT
#define MEASURE_ASSERT 1
#endif

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

// ------------------------------------------------------------ paint method
#define PAINT_BYTE 0xA5
#define PAINT_SIZE (128 * 1024)

static uint8_t* g_lo;          // lowest painted byte

NOINLINE static void paint(void)
{
    volatile uint8_t buf[PAINT_SIZE];
    for (size_t i = 0; i < sizeof(buf); ++i) {
        buf[i] = PAINT_BYTE;
    }
    uint8_t* lo = (uint8_t*)buf;   // only the address is kept, never dereferenced here
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(lo));
#endif
    g_lo = lo;
}

// Bytes in use between `top` and the deepest overwritten painted byte.
static size_t used_below(const uint8_t* top)
{
    const volatile uint8_t* p = g_lo;
    while ((const uint8_t*)p < top && *p == PAINT_BYTE) {
        ++p;
    }
    return (size_t)(top - (const uint8_t*)p);
}

// Repaints from the bottom of the region up to `limit` (exclusive).
static void repaint_below(const uint8_t* limit)
{
    for (volatile uint8_t* p = g_lo; (const uint8_t*)p < limit; ++p) {
        *p = PAINT_BYTE;
    }
}

typedef void (*op_fn)(void);

// Peak stack use of fn(), measured from this frame.
NOINLINE static size_t measure(op_fn fn)
{
    const uint8_t* top = (const uint8_t*)__builtin_frame_address(0);
    paint();
    fn();
    return used_below(top);
}

// ------------------------------------------------------------ fixture
static const uint8_t USER_KEY[32] = { 7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                      12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                      23, 24, 25, 26, 27, 28 };

#define N_OUTS 4

static mw_account_keys_t g_keys;
static uint32_t g_id;
static fx_output_t g_outs[N_OUTS];
static uint8_t g_file[300 * 1024];
static uint8_t g_out[300 * 1024];
static uint8_t g_plain[300 * 1024];
static size_t  g_file_len, g_plain_len;
static mw_sign_session_t g_sess;
static mw_tx_review_t g_rv;
static mw_ops_error_t g_er;
static mw_err_t g_err;
static fx_cd_t g_cd;
static fx_dest_t g_many[MW_MAX_OUTPUTS];      // the 16-output case
static int g_n_many;

static void fresh_store(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_secure_user_key_set(USER_KEY), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_fstore_init(), MW_OK);
}

// ------------------------------------------------------------ operations
static void op_wallet_open(void)
{
    mw_account_keys_t k;
    bool verified = false;
    g_err = mw_wallet_open(g_id, "", &k, &verified);
    mw_memzero(&k, sizeof(k));
}

static void op_outputs_to_keyimages(void)
{
    size_t olen = 0;
    g_err = mw_ops_outputs_to_keyimages(&g_keys, g_file, g_plain_len, g_out, sizeof g_out,
                                        &olen, NULL, &g_er);
}

static void op_inspect(void)
{
    g_err = mw_ops_unsigned_inspect(&g_keys, MW_NET_MAINNET, g_file, g_file_len, &g_sess,
                                    true, &g_rv, &g_er);
}

// Peak of each signing stage, recorded from the progress callback.
#define MAX_STAGES 48
static struct { char label[48]; size_t peak; } g_st[MAX_STAGES];
static int g_nst;
static char g_cur[48];
static const uint8_t* g_sign_top;

static void stage_cb(void* user, const char* stage, uint32_t done, uint32_t total)
{
    (void)user;
    const uint8_t* sp = (const uint8_t*)__builtin_frame_address(0);
    // Everything below this frame belongs to the stage that just ended.
    const uint8_t* limit = sp - 1024;
    if (g_nst < MAX_STAGES && g_cur[0] && strcmp(g_cur, stage) != 0) {
        snprintf(g_st[g_nst].label, sizeof g_st[g_nst].label, "%s", g_cur);
        g_st[g_nst].peak = used_below(g_sign_top);
        g_nst++;
        repaint_below(limit);
    }
    snprintf(g_cur, sizeof g_cur, "%s", stage);
    (void)done;
    (void)total;
}

static size_t g_signed_len;

static void op_sign(void)
{
    mw_ops_cb_t cb = { stage_cb, NULL };
    g_err = mw_ops_unsigned_sign(&g_keys, &g_sess, g_out, sizeof g_out, &g_signed_len, &cb,
                                 &g_er);
}

NOINLINE static size_t measure_sign(void)
{
    const uint8_t* top = (const uint8_t*)__builtin_frame_address(0);
    g_sign_top = top;
    g_nst = 0;
    g_cur[0] = 0;
    paint();
    op_sign();
    size_t last = used_below(top);
    if (g_nst < MAX_STAGES && g_cur[0]) {
        snprintf(g_st[g_nst].label, sizeof g_st[g_nst].label, "%s", g_cur);
        g_st[g_nst].peak = last;
        g_nst++;
    }
    size_t worst = 0;
    for (int i = 0; i < g_nst; ++i) {
        if (g_st[i].peak > worst) worst = g_st[i].peak;
    }
    return worst;
}

static void report(const char* what, size_t peak)
{
    printf("    %-40s %6u B  (budget %u B)\n", what, (unsigned)peak, (unsigned)STACK_BUDGET);
#if MEASURE_ASSERT
    CHECK(peak <= (size_t)STACK_BUDGET);
#endif
}

// ------------------------------------------------------------ unsigned sets
// tools::wallet2::tx_construction_data with any number of destinations
// (fx_cd_t holds 8); otherwise the same layout as fx_write_cd().
static void write_cd_many(mw_writer_t* w, const fx_cd_t* cd, const fx_dest_t* dests,
                          int n_dests)
{
    fx_varint(w, (uint64_t)cd->n_sources);
    for (int i = 0; i < cd->n_sources; ++i) fx_write_source(w, &cd->sources[i]);
    fx_write_dest(w, &cd->change);
    fx_varint(w, (uint64_t)n_dests);                  // splitted_dsts
    for (int i = 0; i < n_dests; ++i) fx_write_dest(w, &dests[i]);
    fx_varint(w, 2);                                  // selected_transfers
    fx_varint(w, 3);
    fx_varint(w, 300);
    fx_varint(w, (uint64_t)cd->extra_len);
    fx_blob(w, cd->extra, (size_t)cd->extra_len);
    fx_u64(w, 0);                                     // unlock_time
    fx_u8(w, (uint8_t)(1u | (cd->view_tags ? 2u : 0u)));
    fx_varint(w, 0);                                  // rct_config
    fx_varint(w, 3);
    fx_varint(w, 4);
    fx_varint(w, (uint64_t)(n_dests - 1));            // dests (w/o change)
    for (int i = 0; i + 1 < n_dests; ++i) fx_write_dest(w, &dests[i]);
    fx_u32(w, cd->subaddr_account);
    fx_varint(w, (uint64_t)cd->n_indices);
    for (int i = 0; i < cd->n_indices; ++i) fx_varint(w, cd->subaddr_indices[i]);
}

static void seal_unsigned(void)
{
    size_t plen;
    if (g_n_many > 0) {
        mw_writer_t w;
        mw_writer_init(&w, g_plain, sizeof g_plain);
        fx_varint(&w, 2);                             // VERSION 2
        fx_varint(&w, 1);                             // one tx
        write_cd_many(&w, &g_cd, g_many, g_n_many);
        fx_varint(&w, 3);                             // tuple<u64, u64, vector>
        fx_varint(&w, 5);
        fx_varint(&w, 5);
        fx_varint(&w, 0);
        CHECK(!w.overflow);
        plen = w.pos;
    } else {
        plen = fx_unsigned_set(&g_cd, 1, NULL, 0, 2, g_plain, sizeof g_plain);
    }
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_UNSIGNED_TX, g_plain, plen, &g_keys, g_file,
                              sizeof g_file, &g_file_len), MW_OK);
}

static void base_cd(const fx_output_t* const* ins, int n_in)
{
    memset(&g_cd, 0, sizeof g_cd);
    g_n_many = 0;
    for (int i = 0; i < n_in; ++i) {
        fx_make_source(&g_cd.sources[i], ins[i], 9 - 3 * i, 98000000 + 1000 * (uint64_t)i);
    }
    g_cd.n_sources = n_in;
    g_cd.view_tags = 1;
    g_cd.subaddr_account = 0;
    g_cd.subaddr_indices[0] = 0;
    g_cd.n_indices = 1;
}

// Feather's extra: tx pub key (33 bytes), with `pid` an encrypted payment id
// nonce (11) as well; wallet2 allows that only with exactly one recipient.
static void feather_extra(int pid)
{
    mw_point_t r;
    fx_random_point(&r);
    uint8_t* e = g_cd.extra;
    e[0] = 0x01;
    memcpy(e + 1, r.b, 32);
    e[33] = 0x02;
    e[34] = 0x09;
    e[35] = 0x01;
    for (int i = 0; i < 8; ++i) e[36 + i] = (uint8_t)(0x10 + i);
    g_cd.extra_len = pid ? 44 : 33;
}

// Inspects, measures signing and checks the signed transaction like a node.
static void run_sign_case(const char* name, int n_in, int n_out)
{
    printf("  %s\n", name);
    seal_unsigned();
    memset(&g_er, 0, sizeof g_er);
    memset(&g_sess, 0, sizeof g_sess);
    size_t peak_inspect = measure(op_inspect);
    CHECK_EQ_INT(g_err, MW_OK);
    if (g_err != MW_OK) {
        printf("    inspect: %s\n", g_er.text);
        return;
    }
    report("mw_ops_unsigned_inspect", peak_inspect);

    size_t peak_sign = measure_sign();
    CHECK_EQ_INT(g_err, MW_OK);
    if (g_err != MW_OK) {
        printf("    sign: %s\n", g_er.text);
        return;
    }
    for (int i = 0; i < g_nst; ++i) {
        printf("      stage %-30s %6u B\n", g_st[i].label, (unsigned)g_st[i].peak);
    }
    report("mw_ops_unsigned_sign", peak_sign);

    static fx_tx_t tx;
    size_t sl = 0;
    CHECK_EQ_INT(mw_file_open(&MW_FILE_SIGNED_TX, g_out, g_signed_len, &g_keys, g_plain,
                              sizeof g_plain, &sl), MW_OK);
    mw_reader_t r;
    uint64_t v = 0;
    mw_reader_init(&r, g_plain, sl);
    mw_read_varint(&r, &v);
    mw_read_varint(&r, &v);
    mw_read_varint(&r, &v);
    CHECK_EQ_INT(fx_decode_tx(g_plain + r.pos, sl - r.pos, &tx), 0);
    CHECK_EQ_INT((int)tx.n_in, n_in);
    CHECK_EQ_INT((int)tx.n_out, n_out);
    CHECK_EQ_INT(fx_verify_tx(g_plain + r.pos, &tx, g_cd.sources, n_in), 0);
}

// ------------------------------------------------------------ tests
MW_TEST(test_setup_and_keyimages)
{
    uint8_t seed[32];
    fresh_store();
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0x21 + 3 * i);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, 32, "", &g_keys), MW_OK);
    CHECK_EQ_INT(mw_wallet_create_pp("stack", MW_SEED_MONERO_LEGACY, seed, 32, 0, NULL,
                                     &g_id), MW_OK);

    printf("  wallet\n");
    size_t peak = measure(op_wallet_open);
    CHECK_EQ_INT(g_err, MW_OK);
    report("mw_wallet_open", peak);
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_keys), MW_OK);

    // Outputs paid to the main address; every one gets its key image.
    fx_make_output(&g_keys, 1, 0, 0, 1626114902ULL, 123456, &g_outs[0]);
    fx_make_output(&g_keys, 0, 0, 0, 3000000000ULL, 123500, &g_outs[1]);
    fx_make_output(&g_keys, 2, 0, 0, 2000000000ULL, 123600, &g_outs[2]);
    fx_make_output(&g_keys, 1, 0, 0, 100000000000000ULL, 123700, &g_outs[3]);

    size_t plen = fx_outputs_plain(&g_keys, g_outs, N_OUTS, 0, N_OUTS, g_plain,
                                   sizeof g_plain);
    mw_ki_export_info_t info;
    memset(&g_er, 0, sizeof g_er);
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, g_plain, plen, &g_keys, g_file,
                              sizeof g_file, &g_file_len), MW_OK);
    CHECK_EQ_INT(mw_ops_outputs_inspect(&g_keys, g_file, g_file_len, &g_plain_len, &info,
                                        &g_er), MW_OK);
    peak = measure(op_outputs_to_keyimages);
    CHECK_EQ_INT(g_err, MW_OK);
    report("mw_ops_outputs_to_keyimages (4 outputs)", peak);
}

MW_TEST(test_device_transaction)
{
    mw_address_t recipient, main_addr;
    fx_foreign_address(&recipient);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 0, &main_addr), MW_OK);
    const fx_output_t* ins[1] = { &g_outs[0] };
    base_cd(ins, 1);
    const uint64_t fee = 30660000ULL, pay = 1000000000ULL;
    fx_dest_from_address(&g_cd.splitted[0], &recipient, pay);
    fx_dest_from_address(&g_cd.change, &main_addr, g_outs[0].amount - pay - fee);
    g_cd.splitted[1] = g_cd.change;
    g_cd.n_splitted = 2;
    feather_extra(1);
    run_sign_case("1 input (ring 16), 2 outputs, encrypted payment id", 1, 2);
}

MW_TEST(test_two_inputs)
{
    mw_address_t recipient, main_addr;
    fx_foreign_address(&recipient);
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 0, &main_addr), MW_OK);
    const fx_output_t* ins[2] = { &g_outs[1], &g_outs[2] };
    base_cd(ins, 2);
    const uint64_t in = g_outs[1].amount + g_outs[2].amount;
    const uint64_t fee = 45000000ULL, pay = 4000000000ULL;
    fx_dest_from_address(&g_cd.splitted[0], &recipient, pay);
    fx_dest_from_address(&g_cd.change, &main_addr, in - pay - fee);
    g_cd.splitted[1] = g_cd.change;
    g_cd.n_splitted = 2;
    feather_extra(1);
    run_sign_case("2 inputs, 2 outputs", 2, 2);
}

MW_TEST(test_sixteen_outputs)
{
    mw_address_t main_addr;
    CHECK_EQ_INT(mw_get_subaddress(&g_keys, 0, 0, &main_addr), MW_OK);
    const fx_output_t* ins[1] = { &g_outs[3] };
    base_cd(ins, 1);
    const uint64_t fee = 200000000ULL, pay = 1000000000ULL;
    g_n_many = MW_MAX_OUTPUTS;
    for (int i = 0; i + 1 < g_n_many; ++i) {
        mw_address_t a;
        fx_foreign_address(&a);
        fx_dest_from_address(&g_many[i], &a, pay + (uint64_t)i);
    }
    uint64_t spent = fee;
    for (int i = 0; i + 1 < g_n_many; ++i) spent += g_many[i].amount;
    fx_dest_from_address(&g_cd.change, &main_addr, g_outs[3].amount - spent);
    g_many[g_n_many - 1] = g_cd.change;
    feather_extra(0);
    run_sign_case("1 input, 16 outputs", 1, MW_MAX_OUTPUTS);
}

int main(void)
{
    // A fixed DRBG source keeps the OS RNG (and its stack use) out of the
    // figures and makes them repeatable.
    static const uint8_t det[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                                     31, 32 };
    mw_random_init();
    mw_random_set_test_source(det, sizeof det);
#if !MEASURE_ASSERT
    printf("  (sanitizer build: figures only, budget not enforced)\n");
#endif

    RUN_TEST(test_setup_and_keyimages);
    RUN_TEST(test_device_transaction);
    RUN_TEST(test_two_inputs);
    RUN_TEST(test_sixteen_outputs);

    mw_host_store_reset();
    return mw_test_summary();
}
