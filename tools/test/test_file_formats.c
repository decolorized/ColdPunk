// Monero / Feather exchange files (file_formats.h).
//
// The payloads are produced by the independent encoder in fx_feather.h,
// written from the wallet2 serialization rules, and fed to the device
// parsers. Every byte parsed here arrives from an online machine, so each
// parser is also run on every truncation of a valid file.
#include <string.h>

#include "test_framework.h"
#include "fx_feather.h"

#include "monero/key_image.h"
#include "monero/address.h"
#include "monero/sign.h"

static mw_account_keys_t g_keys;
static uint8_t g_buf[64 * 1024];
static uint8_t g_buf2[64 * 1024];

// ------------------------------------------------------------ magics
MW_TEST(test_magic_lengths)
{
    CHECK_EQ_INT((int)strlen(MW_MAGIC_OUTPUTS), MW_MAGIC_OUTPUTS_LEN);
    CHECK_EQ_INT((int)strlen(MW_MAGIC_KEYIMAGES), MW_MAGIC_KEYIMAGES_LEN);
    CHECK_EQ_INT((int)strlen(MW_MAGIC_UNSIGNED_TX), MW_MAGIC_UNSIGNED_TX_LEN);
    CHECK_EQ_INT((int)strlen(MW_MAGIC_SIGNED_TX), MW_MAGIC_SIGNED_TX_LEN);
    CHECK_EQ_INT(MW_MAGIC_KEYIMAGES_LEN, 24);
    CHECK_EQ_INT(MW_MAGIC_UNSIGNED_TX_LEN, 22);

    const char* m[4] = {MW_MAGIC_OUTPUTS, MW_MAGIC_KEYIMAGES,
                        MW_MAGIC_UNSIGNED_TX, MW_MAGIC_SIGNED_TX};
    size_t n[4] = {MW_MAGIC_OUTPUTS_LEN, MW_MAGIC_KEYIMAGES_LEN,
                   MW_MAGIC_UNSIGNED_TX_LEN, MW_MAGIC_SIGNED_TX_LEN};
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            if (i == j) continue;
            size_t shorter = n[i] < n[j] ? n[i] : n[j];
            CHECK(memcmp(m[i], m[j], shorter) != 0);
        }
    }
}

// Files are recognised by content, whatever their name (task 3 item 6).
MW_TEST(test_detect_by_magic)
{
    uint8_t f[64];
    memset(f, 0xAB, sizeof f);

    memcpy(f, "Monero output export\004", 21);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_OUTPUTS);
    f[20] = 3;                                        // older export format
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_UNSUPPORTED_VERSION);

    memset(f, 0xAB, sizeof f);
    memcpy(f, "Monero key image export\003", 24);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_KEYIMAGES);

    memset(f, 0xAB, sizeof f);
    memcpy(f, "Monero unsigned tx set\005", 23);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_UNSIGNED_TX);
    f[22] = 4;                                        // boost archive era
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_UNSUPPORTED_VERSION);

    memset(f, 0xAB, sizeof f);
    memcpy(f, "Monero signed tx set\005", 21);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_SIGNED_TX);

    memset(f, 0xAB, sizeof f);
    memcpy(f, "Monero multisig unsigned tx set\001", 32);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_MULTISIG);

    memcpy(f, "PK\003\004", 4);
    CHECK_EQ_INT(mw_file_detect(f, sizeof f), MW_FMT_UNKNOWN);
    CHECK_EQ_INT(mw_file_detect(f, 3), MW_FMT_UNKNOWN);
    CHECK_EQ_INT(mw_file_detect((const uint8_t*)"Monero output", 13), MW_FMT_UNKNOWN);
    CHECK_EQ_INT(mw_file_detect(NULL, 10), MW_FMT_UNKNOWN);
    CHECK(strlen(mw_file_format_name(MW_FMT_UNSIGNED_TX)) > 0);
}

// ------------------------------------------------------------ outputs
static fx_output_t g_outs[6];

static void make_outputs(void)
{
    fx_make_output(&g_keys, 0, 0, 0, 1000000000ULL, 5000, &g_outs[0]);
    fx_make_output(&g_keys, 1, 0, 0, 2000000000ULL, 5001, &g_outs[1]);
    fx_make_output(&g_keys, 3, 1, 3, 3000000000ULL, 5002, &g_outs[2]);   // subaddress
    fx_make_output(&g_keys, 0, 0, 7, 4000000000ULL, 5003, &g_outs[3]);   // subaddress
    fx_make_output(&g_keys, 2, 0, 0, 5000000000ULL, 5004, &g_outs[4]);
    fx_make_output(&g_keys, 5, 2, 1, 6000000000ULL, 5005, &g_outs[5]);   // subaddress
}

MW_TEST(test_outputs_iterate)
{
    size_t len = fx_outputs_plain(&g_keys, g_outs, 6, 42, 48, g_buf, sizeof g_buf);
    mw_outputs_iter_t it;
    mw_ff_diag_t d;
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, len, &g_keys, &d), MW_OK);
    CHECK_EQ_INT((int)it.offset, 42);
    CHECK_EQ_INT((int)it.total, 48);
    CHECK_EQ_INT((int)it.count, 6);

    for (int i = 0; ; ++i) {
        mw_exported_output_t o;
        bool done = false;
        CHECK_EQ_INT(mw_outputs_next(&it, &o, &done, &d), MW_OK);
        if (done) { CHECK_EQ_INT(i, 6); break; }
        CHECK_EQ_MEM(o.one_time_pubkey.b, g_outs[i].one_time.b, 32);
        CHECK_EQ_MEM(o.tx_pub_key.b, g_outs[i].tx_pub.b, 32);
        CHECK_EQ_INT(o.internal_output_index, g_outs[i].idx);
        CHECK_EQ_INT((long long)o.global_output_index, (long long)g_outs[i].global);
        CHECK_EQ_INT((long long)o.amount, (long long)g_outs[i].amount);
        CHECK_EQ_INT(o.subaddr_major, g_outs[i].major);
        CHECK_EQ_INT(o.subaddr_minor, g_outs[i].minor);
        CHECK(o.rct);
        // Only the additional key of THIS output is kept.
        CHECK_EQ_INT(o.has_additional, g_outs[i].n_add > 0);
        if (o.has_additional) {
            CHECK_EQ_MEM(o.additional_tx_pub.b, g_outs[i].add[g_outs[i].idx].b, 32);
            CHECK_EQ_INT((int)o.additional_count, g_outs[i].n_add);
        }
        // Every record is spendable by this account.
        mw_exported_key_image_t ki;
        CHECK_EQ_INT(mw_key_image_from_output(&g_keys, &o, &ki), MW_OK);
        CHECK_EQ_INT(mw_check_key_image_signature(&o.one_time_pubkey, &ki.image,
                                                  &ki.sig), MW_OK);
    }
}

MW_TEST(test_outputs_foreign_account)
{
    mw_account_keys_t other;
    fx_account(&other, 0x77);
    size_t len = fx_outputs_plain(&g_keys, g_outs, 2, 0, 2, g_buf, sizeof g_buf);
    mw_outputs_iter_t it;
    mw_ff_diag_t d;
    memset(&d, 0, sizeof d);
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, len, &other, &d), MW_ERR_KEY_MISMATCH);
    CHECK(strstr(d.what, "different wallet") != NULL);
}

MW_TEST(test_outputs_truncation_and_trailing)
{
    size_t len = fx_outputs_plain(&g_keys, g_outs, 3, 0, 3, g_buf, sizeof g_buf);
    for (size_t n = 0; n < len; ++n) {
        mw_outputs_iter_t it;
        mw_err_t e = mw_outputs_begin(&it, g_buf, n, &g_keys, NULL);
        if (e != MW_OK) continue;
        for (;;) {
            mw_exported_output_t o;
            bool done = false;
            e = mw_outputs_next(&it, &o, &done, NULL);
            if (e != MW_OK || done) break;
        }
        CHECK(e != MW_OK);                  // never a clean finish on a cut file
    }
    // One stray byte after the last record.
    g_buf[len] = 0x00;
    mw_outputs_iter_t it;
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, len + 1, &g_keys, NULL), MW_OK);
    mw_err_t e = MW_OK;
    for (;;) {
        mw_exported_output_t o;
        bool done = false;
        e = mw_outputs_next(&it, &o, &done, NULL);
        if (e != MW_OK || done) break;
    }
    CHECK_EQ_INT(e, MW_ERR_FORMAT);
}

MW_TEST(test_outputs_header_rules)
{
    mw_writer_t w;
    mw_outputs_iter_t it;

    // A count the bytes cannot hold.
    mw_writer_init(&w, g_buf, sizeof g_buf);
    fx_blob(&w, g_keys.pub.spend.b, 32);
    fx_blob(&w, g_keys.pub.view.b, 32);
    fx_varint(&w, 3); fx_varint(&w, 0); fx_varint(&w, 0);
    fx_varint(&w, 1000000);
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, w.pos, &g_keys, NULL), MW_ERR_FORMAT);

    // Not a tuple (the pre-format-4 layout).
    mw_writer_init(&w, g_buf, sizeof g_buf);
    fx_blob(&w, g_keys.pub.spend.b, 32);
    fx_blob(&w, g_keys.pub.view.b, 32);
    fx_varint(&w, 0); fx_varint(&w, 0);
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, w.pos, &g_keys, NULL), MW_ERR_FORMAT);

    // Record version 0.
    mw_writer_init(&w, g_buf, sizeof g_buf);
    fx_blob(&w, g_keys.pub.spend.b, 32);
    fx_blob(&w, g_keys.pub.view.b, 32);
    fx_varint(&w, 3); fx_varint(&w, 0); fx_varint(&w, 1); fx_varint(&w, 1);
    fx_varint(&w, 0);
    for (int i = 0; i < 80; ++i) fx_u8(&w, 1);
    CHECK_EQ_INT(mw_outputs_begin(&it, g_buf, w.pos, &g_keys, NULL), MW_OK);
    {
        mw_exported_output_t o;
        bool done = false;
        CHECK_EQ_INT(mw_outputs_next(&it, &o, &done, NULL), MW_ERR_VERSION);
    }
}

// ------------------------------------------------------------ key images
MW_TEST(test_keyimages_build)
{
    mw_exported_key_image_t kis[4];
    for (int i = 0; i < 4; ++i) {
        mw_exported_output_t o;
        memset(&o, 0, sizeof o);
        o.one_time_pubkey = g_outs[i].one_time;
        o.tx_pub_key = g_outs[i].tx_pub;
        o.internal_output_index = g_outs[i].idx;
        o.subaddr_major = g_outs[i].major;
        o.subaddr_minor = g_outs[i].minor;
        o.has_additional = g_outs[i].n_add > 0;
        if (o.has_additional) o.additional_tx_pub = g_outs[i].add[g_outs[i].idx];
        CHECK_EQ_INT(mw_key_image_from_output(&g_keys, &o, &kis[i]), MW_OK);
    }

    uint8_t out[1024];
    size_t out_len = 0;
    CHECK_EQ_INT(mw_build_keyimages(&g_keys, kis, 4, 7, out, sizeof out, &out_len), MW_OK);
    CHECK_EQ_INT((int)out_len, 4 + 64 + 4 * 96);
    CHECK_EQ_INT(out[0], 7);
    CHECK_EQ_INT(out[1] | out[2] | out[3], 0);
    CHECK_EQ_MEM(out + 4, g_keys.pub.spend.b, 32);
    CHECK_EQ_MEM(out + 36, g_keys.pub.view.b, 32);
    for (int i = 0; i < 4; ++i) {
        CHECK_EQ_MEM(out + 68 + 96 * i, kis[i].image.b, 32);
        CHECK_EQ_MEM(out + 68 + 96 * i + 32, kis[i].sig.c.b, 32);
        CHECK_EQ_MEM(out + 68 + 96 * i + 64, kis[i].sig.r.b, 32);
    }
    size_t q = 0;
    CHECK_EQ_INT(mw_build_keyimages(&g_keys, kis, 4, 7, NULL, 0, &q), MW_OK);
    CHECK_EQ_INT((int)q, (int)out_len);
    CHECK(mw_build_keyimages(&g_keys, kis, 4, 7, out, 8, &q) != MW_OK);
    CHECK_EQ_INT(mw_build_keyimages(NULL, kis, 4, 7, out, sizeof out, &q), MW_ERR_INVALID_ARG);
}

// ------------------------------------------------------------ envelope
MW_TEST(test_schnorr_signature)
{
    uint8_t hash[32];
    mw_keccak256((const uint8_t*)"exchange file", 13, hash);
    uint8_t sig[MW_SIG_LEN];
    CHECK_EQ_INT(mw_schnorr_sign(hash, &g_keys.pub.view, &g_keys.sec.view, sig), MW_OK);
    CHECK_EQ_INT(mw_schnorr_verify(hash, &g_keys.pub.view, sig), MW_OK);
    CHECK(mw_schnorr_verify(hash, &g_keys.pub.spend, sig) != MW_OK);
    for (int i = 0; i < MW_SIG_LEN; ++i) {
        uint8_t bad[MW_SIG_LEN];
        memcpy(bad, sig, sizeof bad);
        bad[i] ^= 0x01;
        CHECK(mw_schnorr_verify(hash, &g_keys.pub.view, bad) != MW_OK);
    }
}

MW_TEST(test_envelope_kinds_and_alias)
{
    uint8_t payload[300];
    for (size_t i = 0; i < sizeof payload; ++i) payload[i] = (uint8_t)(i * 7);
    size_t file_len = 0, out_len = 0;
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, payload, sizeof payload, &g_keys,
                              g_buf, sizeof g_buf, &file_len), MW_OK);
    CHECK_EQ_INT(mw_file_detect(g_buf, file_len), MW_FMT_OUTPUTS);
    CHECK_EQ_INT(mw_file_open(&MW_FILE_UNSIGNED_TX, g_buf, file_len, &g_keys,
                              g_buf2, sizeof g_buf2, &out_len), MW_ERR_MAGIC);

    // Another wallet's view key: the signature does not verify.
    mw_account_keys_t other;
    fx_account(&other, 0x55);
    CHECK_EQ_INT(mw_file_open(&MW_FILE_OUTPUTS, g_buf, file_len, &other,
                              g_buf2, sizeof g_buf2, &out_len), MW_ERR_SIGNATURE);

    // In-place decryption (plaintext aliases the file) must work.
    CHECK_EQ_INT(mw_file_open(&MW_FILE_OUTPUTS, g_buf, file_len, &g_keys,
                              g_buf, file_len, &out_len), MW_OK);
    CHECK_EQ_INT((int)out_len, (int)sizeof payload);
    CHECK_EQ_MEM(g_buf, payload, sizeof payload);

    // Signed set: magic + '\005'.
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_SIGNED_TX, payload, 10, &g_keys,
                              g_buf, sizeof g_buf, &file_len), MW_OK);
    CHECK_EQ_MEM(g_buf, "Monero signed tx set\005", 21);
    CHECK_EQ_INT((int)file_len, 21 + 8 + 10 + 64);

    size_t needed = 0, len = 0;
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, payload, sizeof payload, &g_keys,
                              NULL, 0, &needed), MW_OK);
    for (size_t cap = 0; cap < needed; cap += 13)
        CHECK(mw_file_seal(&MW_FILE_OUTPUTS, payload, sizeof payload, &g_keys,
                           g_buf, cap, &len) != MW_OK);
}

// ------------------------------------------------------------ unsigned set
static fx_cd_t g_cd[2];
static mw_address_t g_recipient;
static const uint8_t g_pid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static void make_cd(fx_cd_t* cd, int which)
{
    memset(cd, 0, sizeof(*cd));
    fx_make_source(&cd->sources[0], &g_outs[which ? 4 : 0], 5, 1000 + 1000u * which);
    fx_make_source(&cd->sources[1], &g_outs[which ? 5 : 2], 11, 2000 + 1000u * which);
    cd->n_sources = 2;
    const uint64_t in = cd->sources[0].real.amount + cd->sources[1].real.amount;
    const uint64_t pay = 1500000000ULL, fee = 30000000ULL;

    fx_dest_from_address(&cd->splitted[0], &g_recipient, pay);
    cd->splitted[0].is_int = 1;
    mw_address_t main;
    mw_get_subaddress(&g_keys, 0, 0, &main);
    fx_dest_from_address(&cd->change, &main, in - pay - fee);
    cd->splitted[1] = cd->change;
    cd->n_splitted = 2;

    cd->extra[0] = 0x02;                   // TX_EXTRA_NONCE
    cd->extra[1] = 9;
    cd->extra[2] = 0x01;                   // encrypted payment id (plain here)
    memcpy(cd->extra + 3, g_pid, 8);
    cd->extra_len = 11;
    cd->subaddr_account = 0;
    cd->subaddr_indices[0] = 0;
    cd->subaddr_indices[1] = 3;
    cd->n_indices = 2;
    cd->view_tags = 1;
}

MW_TEST(test_unsigned_parse_and_load)
{
    static mw_unsigned_set_t set;
    static mw_transaction_t tx;
    fx_account(&g_keys, 0x21);
    make_outputs();
    fx_foreign_address(&g_recipient);
    make_cd(&g_cd[0], 0);
    make_cd(&g_cd[1], 1);

    size_t len = fx_unsigned_set(g_cd, 2, &g_outs[1], 2, 2, g_buf, sizeof g_buf);
    mw_ff_diag_t d;
    memset(&d, 0, sizeof d);
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, &d), MW_OK);
    CHECK_EQ_INT(set.version, 2);
    CHECK_EQ_INT(set.n_txes, 2);
    CHECK_EQ_INT((int)set.nt_count, 2);
    CHECK_EQ_INT((int)set.nt_offset, 5);
    CHECK_EQ_INT((int)set.nt_total, 7);

    const mw_utx_entry_t* e = &set.tx[0];
    CHECK_EQ_INT(e->n_sources, 2);
    CHECK_EQ_INT(e->n_splitted, 2);
    CHECK_EQ_INT(e->n_dests, 1);
    CHECK_EQ_INT(e->n_subaddr_indices, 2);
    CHECK_EQ_INT(e->construction_flags, 3);
    CHECK_EQ_INT(e->bp_version, 4);
    // The record spans tile the construction data.
    CHECK_EQ_INT(e->cd.off, e->sources.off);
    CHECK_EQ_INT(e->sources.off + e->sources.len, e->change_dts.off);
    CHECK_EQ_INT(e->change_dts.off + e->change_dts.len, e->splitted_dsts.off);
    CHECK_EQ_INT(e->splitted_dsts.off + e->splitted_dsts.len, e->selected_transfers.off);
    CHECK_EQ_INT(set.tx[1].cd.off, e->cd.off + e->cd.len);

    CHECK_EQ_INT(mw_unsigned_set_load_tx(&set, 0, &tx, &d), MW_OK);
    CHECK_EQ_INT(tx.n_inputs, 2);
    CHECK_EQ_INT(tx.n_destinations, 2);
    CHECK_EQ_INT(tx.rct_type, 6);
    CHECK(tx.use_view_tags);
    CHECK_EQ_INT((long long)tx.fee, 30000000LL);
    CHECK_EQ_INT(tx.sources[0].ring_size, FX_RING);
    CHECK_EQ_INT(tx.sources[0].real_output_index, 5);
    CHECK_EQ_INT((long long)tx.sources[0].key_offsets[0], 1000LL);
    for (int k = 1; k < FX_RING; ++k)
        CHECK_EQ_INT((long long)tx.sources[0].key_offsets[k], 10LL);
    CHECK(!tx.sources[0].has_additional_key);
    CHECK(tx.sources[1].has_additional_key);        // subaddress input
    CHECK_EQ_MEM(tx.sources[1].real_out_additional_key.b,
                 g_outs[2].add[g_outs[2].idx].b, 32);
    CHECK_EQ_INT(tx.sources[1].real_output_in_tx_index, g_outs[2].idx);
    CHECK_EQ_MEM(tx.sources[1].mask.b, g_outs[2].mask.b, 32);
    CHECK(tx.has_change_addr);
    CHECK_EQ_MEM(tx.change_addr.spend.b, g_keys.pub.spend.b, 32);
    CHECK_EQ_INT(tx.extra_in_len, 11);
    CHECK_EQ_MEM(tx.extra_in, g_cd[0].extra, 11);
    CHECK_EQ_INT(tx.n_subaddr_hints, 2);
    CHECK_EQ_INT(tx.subaddr_hints[1], 3);
    CHECK(tx.destinations[0].is_integrated);
    CHECK(!tx.destinations[0].is_change);            // decided by the checker

    // Destination check + summary: the integrated recipient, change shown
    // apart. The check needs matched inputs, all in subaddr_account: the
    // second input of this fixture is in account 1, so it must be refused
    // until only the account-0 input is left.
    static mw_transaction_t tx1;
    tx1 = tx;
    mw_keyimage_t ki;
    tx1.sources[1].subaddr_known = true;
    tx1.sources[1].subaddr_major = 1;
    tx1.sources[1].subaddr_minor = 3;
    CHECK_EQ_INT(mw_sign_input_key_image(&g_keys, &tx1, 0, &ki), MW_OK);
    mw_tx_check_info_t ci;
    CHECK_EQ_INT(mw_tx_check_destinations(&g_keys, &tx1, &ci), MW_ERR_KEY_MISMATCH);
    CHECK_EQ_INT(ci.reason, MW_TXR_ACCOUNT);
    tx1.n_inputs = 1;
    CHECK_EQ_INT(mw_tx_check_destinations(&g_keys, &tx1, &ci), MW_OK);
    CHECK(tx1.change_verified);
    CHECK(tx1.destinations[1].is_change);
    mw_tx_summary_t sum;
    CHECK_EQ_INT(mw_tx_summarize(&tx1, MW_NET_MAINNET, &sum), MW_OK);
    CHECK_EQ_INT(sum.n_recipients, 1);
    CHECK_EQ_INT((int)strlen(sum.recipients[0]), 106);
    CHECK(!sum.recipient_own[0]);
    CHECK_EQ_INT((long long)sum.total_out, 1500000000LL);
    CHECK(sum.has_change);
    CHECK_EQ_INT((int)strlen(sum.change_addr), 95);
    CHECK_EQ_INT(sum.change_addr[0], '4');

    // new_transfers reader.
    mw_outputs_iter_t it;
    mw_unsigned_set_new_transfers(&set, &it);
    int n = 0;
    for (;;) {
        mw_exported_output_t o;
        bool done = false;
        CHECK_EQ_INT(mw_outputs_next(&it, &o, &done, NULL), MW_OK);
        if (done) break;
        CHECK_EQ_MEM(o.one_time_pubkey.b, g_outs[1 + n].one_time.b, 32);
        n++;
    }
    CHECK_EQ_INT(n, 2);

    // Version 1: pair<size_t, vector>.
    len = fx_unsigned_set(g_cd, 1, &g_outs[1], 1, 1, g_buf, sizeof g_buf);
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, NULL), MW_OK);
    CHECK_EQ_INT(set.version, 1);
    CHECK_EQ_INT((int)set.nt_count, 1);
}

MW_TEST(test_unsigned_rejects)
{
    static mw_unsigned_set_t set;
    static mw_transaction_t tx;
    size_t len = fx_unsigned_set(g_cd, 1, &g_outs[1], 1, 2, g_buf, sizeof g_buf);
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, NULL), MW_OK);

    // Every truncation, and a trailing byte.
    for (size_t n = 0; n < len; ++n)
        CHECK(mw_unsigned_set_parse(g_buf, n, &set, NULL) != MW_OK);
    g_buf[len] = 0;
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len + 1, &set, NULL), MW_ERR_FORMAT);

    // Versions.
    uint8_t save = g_buf[0];
    g_buf[0] = 0;
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, NULL), MW_ERR_VERSION);
    g_buf[0] = 3;
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, NULL), MW_ERR_VERSION);
    g_buf[0] = save;

    // Too many transactions in one set.
    {
        static fx_cd_t many[MW_MAX_TXES_PER_SET + 1];
        for (int i = 0; i <= MW_MAX_TXES_PER_SET; ++i) many[i] = g_cd[0];
        size_t l = fx_unsigned_set(many, MW_MAX_TXES_PER_SET + 1, NULL, 0, 2, g_buf,
                                   sizeof g_buf);
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_ERR_NOT_SUPPORTED);
    }

    // Ring indices not increasing.
    {
        fx_cd_t cd = g_cd[0];
        cd.sources[0].global[4] = cd.sources[0].global[3];
        size_t l = fx_unsigned_set(&cd, 1, NULL, 0, 2, g_buf, sizeof g_buf);
        mw_ff_diag_t d;
        memset(&d, 0, sizeof d);
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, &d), MW_ERR_FORMAT);
        CHECK(strstr(d.what, "increasing") != NULL);
    }

    // Outputs exceeding inputs.
    {
        fx_cd_t cd = g_cd[0];
        cd.splitted[0].amount += 1000000000000ULL;
        size_t l = fx_unsigned_set(&cd, 1, NULL, 0, 2, g_buf, sizeof g_buf);
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_ERR_BALANCE);
    }

    // Not RingCT / old bulletproofs: parsed, but refused when loaded.
    {
        size_t l = fx_unsigned_set(g_cd, 1, NULL, 0, 2, g_buf, sizeof g_buf);
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_OK);
        g_buf[set.tx[0].extra.off + set.tx[0].extra.len + 8] = 0x02;   // flags: !rct
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_OK);
        CHECK_EQ_INT(mw_unsigned_set_load_tx(&set, 0, &tx, NULL), MW_ERR_NOT_SUPPORTED);
        g_buf[set.tx[0].extra.off + set.tx[0].extra.len + 8] = 0x03;
        g_buf[set.tx[0].extra.off + set.tx[0].extra.len + 11] = 3;     // bp_version 3
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_OK);
        CHECK_EQ_INT(mw_unsigned_set_load_tx(&set, 0, &tx, NULL), MW_ERR_NOT_SUPPORTED);
        g_buf[set.tx[0].extra.off + set.tx[0].extra.len + 11] = 4;
        g_buf[set.tx[0].extra.off + set.tx[0].extra.len] = 1;          // unlock_time
        CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, l, &set, NULL), MW_OK);
        CHECK_EQ_INT(mw_unsigned_set_load_tx(&set, 0, &tx, NULL), MW_ERR_NOT_SUPPORTED);
    }
}

// ------------------------------------------------------------ signed set
MW_TEST(test_signed_set_layout)
{
    static mw_unsigned_set_t set;
    size_t len = fx_unsigned_set(g_cd, 2, &g_outs[1], 1, 2, g_buf, sizeof g_buf);
    CHECK_EQ_INT(mw_unsigned_set_parse(g_buf, len, &set, NULL), MW_OK);

    uint8_t blob0[40], blob1[57];
    for (size_t i = 0; i < sizeof blob0; ++i) blob0[i] = (uint8_t)(0xB0 + i);
    for (size_t i = 0; i < sizeof blob1; ++i) blob1[i] = (uint8_t)(0x10 + i);
    mw_keyimage_t vin0[2], vin1[1];
    fx_random_point(&vin0[0]); fx_random_point(&vin0[1]); fx_random_point(&vin1[0]);
    mw_signed_ptx_t ptx[2] = {
        { blob0, sizeof blob0, 111, vin0, 2 },
        { blob1, sizeof blob1, 222, vin1, 1 },
    };
    mw_ki_pair_t kis[3];
    for (int i = 0; i < 3; ++i) { fx_random_point(&kis[i].out_pub); fx_random_point(&kis[i].image); }

    size_t need = 0, out_len = 0;
    CHECK_EQ_INT(mw_build_signed_set(&set, ptx, 2, kis, 3, NULL, 0, &need), MW_OK);
    CHECK_EQ_INT(mw_build_signed_set(&set, ptx, 2, kis, 3, g_buf2, sizeof g_buf2, &out_len), MW_OK);
    CHECK(out_len <= need);
    CHECK(mw_build_signed_set(&set, ptx, 1, kis, 3, g_buf2, sizeof g_buf2, &out_len) != MW_OK);

    // Decode it the way parse_tx_from_str() would.
    mw_reader_t r;
    uint64_t v = 0;
    mw_reader_init(&r, g_buf2, out_len);
    CHECK(mw_read_varint(&r, &v) && v == 0);            // signed_tx_set version
    CHECK(mw_read_varint(&r, &v) && v == 2);            // ptx
    for (int i = 0; i < 2; ++i) {
        const mw_utx_entry_t* e = &set.tx[i];
        uint64_t u = 0;
        uint8_t b = 0;
        CHECK(mw_read_varint(&r, &v) && v == 1);        // pending_tx version
        uint8_t tmp[64];
        CHECK(mw_read_bytes(&r, tmp, ptx[i].tx_blob_len));
        CHECK_EQ_MEM(tmp, ptx[i].tx_blob, ptx[i].tx_blob_len);
        CHECK(mw_read_u64(&r, &u) && u == 0);           // dust
        CHECK(mw_read_u64(&r, &u) && u == ptx[i].fee);  // fee
        CHECK(mw_read_u8(&r, &b) && b == 0);            // dust_added_to_fee
        CHECK_EQ_MEM(g_buf2 + r.pos, g_buf + e->change_dts.off, e->change_dts.len);
        mw_skip(&r, e->change_dts.len);
        CHECK_EQ_MEM(g_buf2 + r.pos, g_buf + e->selected_transfers.off, e->selected_transfers.len);
        mw_skip(&r, e->selected_transfers.len);
        CHECK(mw_read_varint(&r, &v) && v == 67u * ptx[i].n_vin);   // key_images
        CHECK_EQ_INT(g_buf2[r.pos], '<');
        CHECK_EQ_INT(g_buf2[r.pos + 65], '>');
        CHECK_EQ_INT(g_buf2[r.pos + 66], ' ');
        mw_skip(&r, (size_t)v);
        uint8_t key[32];
        CHECK(mw_read_bytes(&r, key, 32));              // tx_key = identity
        CHECK_EQ_INT(key[0], 1);
        for (int k = 1; k < 32; ++k) CHECK_EQ_INT(key[k], 0);
        CHECK(mw_read_varint(&r, &v) && v == 0);        // additional_tx_keys
        CHECK_EQ_MEM(g_buf2 + r.pos, g_buf + e->dests.off, e->dests.len);
        mw_skip(&r, e->dests.len);
        CHECK_EQ_MEM(g_buf2 + r.pos, g_buf + e->cd.off, e->cd.len);
        mw_skip(&r, e->cd.len);
        CHECK(mw_read_varint(&r, &v) && v == 0);        // multisig_sigs
        CHECK(mw_read_bytes(&r, key, 32));              // multisig_tx_key_entropy
    }
    CHECK(mw_read_varint(&r, &v) && v == 0);            // key_images
    CHECK(mw_read_varint(&r, &v) && v == 3);            // tx_key_images
    for (int i = 0; i < 3; ++i) {
        mw_point_t a, b;
        CHECK(mw_read_varint(&r, &v) && v == 2);
        CHECK(mw_read_point(&r, &a) && mw_read_point(&r, &b));
        CHECK_EQ_MEM(a.b, kis[i].out_pub.b, 32);
        CHECK_EQ_MEM(b.b, kis[i].image.b, 32);
    }
    CHECK_EQ_INT((int)mw_remaining(&r), 0);
    CHECK(!r.overflow);
}

int main(void)
{
    mw_random_init();
    fx_account(&g_keys, 0x21);
    make_outputs();

    RUN_TEST(test_magic_lengths);
    RUN_TEST(test_detect_by_magic);
    RUN_TEST(test_outputs_iterate);
    RUN_TEST(test_outputs_foreign_account);
    RUN_TEST(test_outputs_truncation_and_trailing);
    RUN_TEST(test_outputs_header_rules);
    RUN_TEST(test_keyimages_build);
    RUN_TEST(test_schnorr_signature);
    RUN_TEST(test_envelope_kinds_and_alias);
    RUN_TEST(test_unsigned_parse_and_load);
    RUN_TEST(test_unsigned_rejects);
    RUN_TEST(test_signed_set_layout);

    return mw_test_summary();
}
