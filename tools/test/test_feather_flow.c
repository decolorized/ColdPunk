// End-to-end Feather cold-signing flow on the host (task 3):
//
//   wallet with a passphrase (two wallets per seed)  ->  open / verify
//   Feather outputs export  ->  key image export (and the device cache)
//   Feather unsigned tx set ->  review  ->  signed tx set
//
// The files are built by the independent encoder of fx_feather.h, sealed the
// way wallet2::encrypt_with_view_secret_key() does, and every file the device
// produces is decrypted and decoded here without the device parsers. The
// signed transaction is verified like a node would verify it (CLSAG, BP+,
// balance).
#include <string.h>

#include "test_framework.h"
#include "fx_feather.h"

#include "crypto/memzero.h"
#include "hal/log.h"
#include "monero/address.h"
#include "monero/key_image.h"
#include "monero/mnemonic.h"
#include "wallet/file_store.h"
#include "wallet/ki_cache.h"
#include "wallet/secure_storage.h"
#include "wallet/wallet_ops.h"
#include "wallet/wallet_store.h"

void mw_host_store_set_dir(const char* dir);
void mw_host_store_reset(void);

#define STORE_DIR "./.mw_test_flow"

static const uint8_t USER_KEY[32] = { 7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                      12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                      23, 24, 25, 26, 27, 28 };

static uint8_t g_seed[32];
static uint32_t g_id;
static mw_account_keys_t g_base, g_pp;
static uint8_t g_file[128 * 1024];
static uint8_t g_out[128 * 1024];
static uint8_t g_plain[128 * 1024];
static mw_sign_session_t g_sess;

static void fresh_store(void)
{
    mw_host_store_set_dir(STORE_DIR);
    mw_host_store_reset();
    CHECK_EQ_INT(mw_secure_key_provision(), MW_OK);
    CHECK_EQ_INT(mw_secure_user_key_set(USER_KEY), MW_OK);
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_fstore_init(), MW_OK);
}

// ------------------------------------------------------------ passphrase
MW_TEST(test_two_wallets_per_seed)
{
    fresh_store();
    for (int i = 0; i < 32; ++i) g_seed[i] = (uint8_t)(0x40 + i);

    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, g_seed, 32, "", &g_base), MW_OK);
    CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_MONERO_LEGACY, g_seed, 32, "correct horse", &g_pp),
                 MW_OK);
    CHECK(!mw_point_eq(&g_base.pub.spend, &g_pp.pub.spend));

    CHECK_EQ_INT(mw_wallet_create_pp("borya", MW_SEED_MONERO_LEGACY, g_seed, 32, 3100000,
                                     &g_pp, &g_id), MW_OK);
    CHECK_EQ_INT(mw_wallet_pp_state(g_id), MW_PP_SET);

    mw_account_keys_t k;
    bool verified = false;
    // Empty passphrase: the base wallet.
    CHECK_EQ_INT(mw_wallet_open(g_id, "", &k, &verified), MW_OK);
    CHECK(verified);
    CHECK_EQ_MEM(k.pub.spend.b, g_base.pub.spend.b, 32);
    // The right passphrase: the passphrase wallet, verified.
    CHECK_EQ_INT(mw_wallet_open(g_id, "correct horse", &k, &verified), MW_OK);
    CHECK(verified);
    CHECK_EQ_MEM(k.pub.spend.b, g_pp.pub.spend.b, 32);
    CHECK_EQ_MEM(k.sec.view.b, g_pp.sec.view.b, 32);
    // A wrong one is refused and leaves no keys behind.
    CHECK_EQ_INT(mw_wallet_open(g_id, "correct horsf", &k, &verified), MW_ERR_DECRYPT);
    CHECK(!verified);
    {
        static const uint8_t zero[sizeof k] = {0};
        CHECK_EQ_MEM(&k, zero, sizeof k);
    }

    // A wallet created without a passphrase never asks and refuses one.
    uint32_t id2 = 0;
    uint8_t seed2[32];
    memset(seed2, 0x31, sizeof seed2);
    CHECK_EQ_INT(mw_wallet_create_pp("plain", MW_SEED_MONERO_LEGACY, seed2, 32, 0, NULL, &id2),
                 MW_OK);
    CHECK_EQ_INT(mw_wallet_pp_state(id2), MW_PP_NONE);
    CHECK_EQ_INT(mw_wallet_open(id2, "x", &k, &verified), MW_ERR_INVALID_ARG);
    CHECK_EQ_INT(mw_wallet_open(id2, "", &k, &verified), MW_OK);

    // The state survives a reload of the directory, and a rekey.
    CHECK_EQ_INT(mw_wallet_store_init(), MW_OK);
    CHECK_EQ_INT(mw_wallet_pp_state(g_id), MW_PP_SET);
    {
        uint8_t nk[32];
        memset(nk, 0x5a, sizeof nk);
        CHECK_EQ_INT(mw_wallet_store_rekey(USER_KEY, nk), MW_OK);
        CHECK_EQ_INT(mw_wallet_open(g_id, "correct horse", &k, &verified), MW_OK);
        CHECK(verified);
        CHECK_EQ_INT(mw_wallet_store_rekey(nk, USER_KEY), MW_OK);
    }

    // Polyseed too.
    {
        mw_polyseed_t ps;
        uint8_t ent[32], blob[MW_POLYSEED_BLOB_MAX];
        size_t blen = 0;
        uint32_t id3 = 0;
        mw_account_keys_t pk;
        memset(ent, 0x19, sizeof ent);
        CHECK_EQ_INT(mw_polyseed_create(ent, sizeof ent, 1700000000ULL, 0, &ps), MW_OK);
        CHECK_EQ_INT(mw_polyseed_pack(&ps, blob, sizeof blob, &blen), MW_OK);
        CHECK_EQ_INT(mw_seed_to_keys(MW_SEED_POLYSEED, blob, blen, "pp", &pk), MW_OK);
        CHECK_EQ_INT(mw_wallet_create_pp("poly", MW_SEED_POLYSEED, blob, blen, 0, &pk, &id3),
                     MW_OK);
        CHECK_EQ_INT(mw_wallet_open(id3, "pp", &k, &verified), MW_OK);
        CHECK(verified);
        CHECK_EQ_INT(mw_wallet_open(id3, "pq", &k, &verified), MW_ERR_DECRYPT);
        CHECK_EQ_INT(mw_wallet_delete(id3), MW_OK);
    }
    CHECK_EQ_INT(mw_wallet_delete(id2), MW_OK);
    mw_memzero(&k, sizeof k);
}

// ------------------------------------------------------------ key images
static fx_output_t g_outs[5];

MW_TEST(test_outputs_to_key_images)
{
    fx_make_output(&g_base, 0, 0, 0, 3000000000000ULL, 700, &g_outs[0]);
    fx_make_output(&g_base, 1, 0, 0, 1000000000000ULL, 701, &g_outs[1]);
    fx_make_output(&g_base, 2, 1, 3, 2000000000000ULL, 702, &g_outs[2]);   // subaddress
    fx_make_output(&g_base, 0, 0, 5, 500000000000ULL, 703, &g_outs[3]);    // subaddress
    fx_make_output(&g_base, 4, 0, 0, 700000000000ULL, 704, &g_outs[4]);

    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_count(), 0);

    // What Feather's "export outputs" writes: 4 of the 5 (the last one is
    // not synchronised yet).
    size_t plen = fx_outputs_plain(&g_base, g_outs, 4, 10, 14, g_plain, sizeof g_plain);
    size_t flen = 0;
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, g_plain, plen, &g_base, g_file,
                              sizeof g_file, &flen), MW_OK);
    CHECK_EQ_INT(mw_file_detect(g_file, flen), MW_FMT_OUTPUTS);

    // The passphrase variant cannot open it: different view key.
    {
        static uint8_t copy[sizeof g_file];
        mw_ops_error_t er;
        mw_ki_export_info_t info;
        size_t pl = 0;
        memcpy(copy, g_file, flen);
        memset(&er, 0, sizeof er);
        CHECK_EQ_INT(mw_ops_outputs_inspect(&g_pp, copy, flen, &pl, &info, &er),
                     MW_ERR_SIGNATURE);
        CHECK(strstr(er.text, "different wallet") != NULL);
    }

    mw_ops_error_t er;
    mw_ki_export_info_t info;
    size_t pl = 0;
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_outputs_inspect(&g_base, g_file, flen, &pl, &info, &er), MW_OK);
    CHECK_EQ_INT((int)info.count, 4);
    CHECK_EQ_INT((int)info.offset, 10);
    CHECK_EQ_INT(info.known, 0);

    size_t olen = 0;
    CHECK_EQ_INT(mw_ops_outputs_to_keyimages(&g_base, g_file, pl, g_out, sizeof g_out,
                                             &olen, NULL, &er), MW_OK);
    CHECK_EQ_INT(mw_file_detect(g_out, olen), MW_FMT_KEYIMAGES);

    // import_key_images_from_str(): decrypt, header, 96-byte records.
    size_t kl = 0;
    CHECK_EQ_INT(mw_file_open(&MW_FILE_KEYIMAGES, g_out, olen, &g_base, g_plain,
                              sizeof g_plain, &kl), MW_OK);
    CHECK_EQ_INT((int)kl, 68 + 4 * 96);
    CHECK_EQ_INT(g_plain[0], 10);
    CHECK_EQ_MEM(g_plain + 4, g_base.pub.spend.b, 32);
    CHECK_EQ_MEM(g_plain + 36, g_base.pub.view.b, 32);
    for (int i = 0; i < 4; ++i) {
        mw_keyimage_t ki;
        mw_ring_sig_t sig;
        memcpy(ki.b, g_plain + 68 + 96 * i, 32);
        memcpy(sig.c.b, g_plain + 68 + 96 * i + 32, 32);
        memcpy(sig.r.b, g_plain + 68 + 96 * i + 64, 32);
        // Feather brute-forces key image <-> output with exactly this check.
        CHECK_EQ_INT(mw_check_key_image_signature(&g_outs[i].one_time, &ki, &sig), MW_OK);
        const mw_ki_entry_t* e = mw_ki_cache_find_image(&ki);
        CHECK(e != NULL);
        if (e) {
            CHECK_EQ_INT(e->major, g_outs[i].major);
            CHECK_EQ_INT(e->minor, g_outs[i].minor);
            CHECK(e->flags & MW_KI_F_EXPORTED);
        }
    }
    CHECK_EQ_INT(mw_ki_cache_count(), 4);

    // A second pass over the same file finds them known.
    plen = fx_outputs_plain(&g_base, g_outs, 4, 10, 14, g_plain, sizeof g_plain);
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, g_plain, plen, &g_base, g_file,
                              sizeof g_file, &flen), MW_OK);
    CHECK_EQ_INT(mw_ops_outputs_inspect(&g_base, g_file, flen, &pl, &info, &er), MW_OK);
    CHECK_EQ_INT(info.known, 4);

    // An output of somebody else in the file fails the WHOLE export.
    {
        mw_account_keys_t other;
        fx_output_t mixed[2];
        fx_account(&other, 0x99);
        mixed[0] = g_outs[0];
        fx_make_output(&other, 0, 0, 0, 1, 1, &mixed[1]);
        plen = fx_outputs_plain(&g_base, mixed, 2, 0, 2, g_plain, sizeof g_plain);
        CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, g_plain, plen, &g_base, g_file,
                                  sizeof g_file, &flen), MW_OK);
        CHECK_EQ_INT(mw_ops_outputs_inspect(&g_base, g_file, flen, &pl, &info, &er), MW_OK);
        CHECK_EQ_INT(mw_ops_outputs_to_keyimages(&g_base, g_file, pl, g_out, sizeof g_out,
                                                 &olen, NULL, &er), MW_ERR_KEY_MISMATCH);
        CHECK(strstr(er.text, "does not belong") != NULL);
    }

    // The cache survives close / reopen (sealed file).
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    mw_ki_cache_close();
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_count(), 4);
    // ... but not under another account.
    mw_ki_cache_close();
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_pp), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_count(), 0);
    mw_ki_cache_close();
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
}

// ------------------------------------------------------------ signing
static fx_cd_t g_cd;
static mw_address_t g_recipient;

static void make_cd(const fx_output_t* a, const fx_output_t* b, uint64_t pay)
{
    memset(&g_cd, 0, sizeof g_cd);
    fx_make_source(&g_cd.sources[0], a, 3, 90000);
    fx_make_source(&g_cd.sources[1], b, 12, 95000);
    g_cd.n_sources = 2;
    const uint64_t in = a->amount + b->amount, fee = 45000000ULL;
    fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
    mw_address_t main;
    mw_get_subaddress(&g_base, 0, 0, &main);
    fx_dest_from_address(&g_cd.change, &main, in - pay - fee);
    g_cd.splitted[1] = g_cd.change;
    g_cd.n_splitted = 2;
    g_cd.view_tags = 1;
    g_cd.subaddr_account = 0;
}

static size_t sealed_unsigned(const fx_output_t* nt, int n_nt)
{
    size_t plen = fx_unsigned_set(&g_cd, 1, nt, n_nt, 2, g_plain, sizeof g_plain);
    size_t flen = 0;
    CHECK_EQ_INT(mw_file_seal(&MW_FILE_UNSIGNED_TX, g_plain, plen, &g_base, g_file,
                              sizeof g_file, &flen), MW_OK);
    return flen;
}

MW_TEST(test_unsigned_to_signed)
{
    static fx_tx_t tx;
    fx_foreign_address(&g_recipient);
    // Input 2 is on subaddress (0,5): the device finds it through the cache.
    // (Both inputs in account 0: wallet2 never spends two accounts at once.)
    make_cd(&g_outs[0], &g_outs[3], 3000000000000ULL);
    size_t flen = sealed_unsigned(&g_outs[1], 1);
    CHECK_EQ_INT(mw_file_detect(g_file, flen), MW_FMT_UNSIGNED_TX);

    mw_tx_review_t rv;
    mw_ops_error_t er;
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_OK);
    if (er.text[0]) printf("    inspect: %s\n", er.text);
    CHECK_EQ_INT(rv.n_txes, 1);
    CHECK_EQ_INT(rv.sum[0].n_recipients, 1);
    CHECK_EQ_INT((long long)rv.total_out, 3000000000000LL);
    CHECK_EQ_INT((long long)rv.total_fee, 45000000LL);
    CHECK_EQ_INT((long long)rv.total_change,
                 (long long)(3500000000000ULL - 3000000000000ULL - 45000000ULL));
    // Bug 3: the user's exact shape (1 recipient + change to the main
    // address) shows the change with its address.
    {
        mw_address_t main_addr;
        char str[MW_ADDRESS_STR_MAX];
        CHECK_EQ_INT(mw_address_from_keys(&g_base, MW_NET_MAINNET, &main_addr), MW_OK);
        CHECK_EQ_INT(mw_address_encode(&main_addr, str, sizeof str), MW_OK);
        CHECK(rv.sum[0].has_change);
        CHECK_EQ_STR(rv.sum[0].change_addr, str);
        CHECK_EQ_INT((int)rv.sum[0].change_major, 0);
        CHECK_EQ_INT((int)rv.sum[0].change_minor, 0);
        CHECK(!rv.sum[0].recipient_own[0]);
        CHECK_EQ_INT(rv.sum[0].n_dummy, 0);
        CHECK(!rv.sum[0].high_fee);
    }
    CHECK(g_sess.has_file_key);
    CHECK_EQ_INT(rv.spent_before, 0);
    CHECK_EQ_INT((int)rv.new_transfers, 1);

    size_t olen = 0;
    CHECK_EQ_INT(mw_ops_unsigned_sign(&g_base, &g_sess, g_out, sizeof g_out, &olen, NULL,
                                      &er), MW_OK);
    if (er.text[0]) printf("    sign: %s\n", er.text);
    CHECK_EQ_INT(mw_file_detect(g_out, olen), MW_FMT_SIGNED_TX);
    CHECK(!g_sess.has_file_key);                      // the cached key is wiped
    {
        static const mw_chacha_key zero_key;
        CHECK_EQ_MEM(&g_sess.file_key, &zero_key, sizeof zero_key);
    }

    // parse_tx_from_str(): decrypt and decode the signed_tx_set.
    size_t sl = 0;
    CHECK_EQ_INT(mw_file_open(&MW_FILE_SIGNED_TX, g_out, olen, &g_base, g_plain,
                              sizeof g_plain, &sl), MW_OK);
    mw_reader_t r;
    uint64_t v = 0, fee = 0, dust = 1;
    mw_reader_init(&r, g_plain, sl);
    CHECK(mw_read_varint(&r, &v) && v == 0);
    CHECK(mw_read_varint(&r, &v) && v == 1);
    CHECK(mw_read_varint(&r, &v) && v == 1);          // pending_tx version
    const size_t tx_off = r.pos;
    CHECK_EQ_INT(fx_decode_tx(g_plain + tx_off, sl - tx_off, &tx), 0);
    CHECK_EQ_INT(fx_verify_tx(g_plain + tx_off, &tx, g_cd.sources, 2), 0);
    CHECK_EQ_INT(tx.n_in, 2);
    CHECK_EQ_INT(tx.n_out, 2);
    CHECK_EQ_INT((long long)tx.fee, 45000000LL);
    CHECK(memcmp(tx.ki[0].b, tx.ki[1].b, 32) > 0);   // sorted descending
    mw_skip(&r, tx.len);
    CHECK(mw_read_u64(&r, &dust) && dust == 0);
    CHECK(mw_read_u64(&r, &fee) && fee == 45000000ULL);

    // The recipient can find its output: one of the two derives from 8*r*A,
    // which it computes as 8*a*R with its view key - here we only check that
    // our own change is found with our view key and decodes to the change.
    {
        mw_pubkey_t R;
        CHECK_EQ_INT(tx.extra[0], 0x01);
        memcpy(R.b, tx.extra + 1, 32);
        mw_point_t der;
        CHECK_EQ_INT(mw_generate_key_derivation(&R, &g_base.sec.view, &der), MW_OK);
        int found = 0;
        for (uint32_t i = 0; i < tx.n_out; ++i) {
            mw_pubkey_t p;
            CHECK_EQ_INT(mw_derive_public_key(&der, i, &g_base.pub.spend, &p), MW_OK);
            if (!mw_point_eq(&p, &tx.out_key[i])) continue;
            found++;
            mw_scalar_t ak;
            mw_ecdh_mask_t mask;
            uint64_t amount = 0;
            mw_derivation_to_scalar(&der, i, &ak);
            memcpy(&amount, tx.ecdh[i], 8);
            mw_ecdh_decode(&ak, &amount, &mask);
            CHECK_EQ_INT((long long)amount, (long long)rv.total_change);
        }
        CHECK_EQ_INT(found, 1);
    }

    // tx_key_images: our change output and the requested transfer.
    {
        // Skip the rest of the pending_tx to reach the map.
        const mw_utx_entry_t* e = &g_sess.set.tx[0];
        uint8_t b;
        CHECK(mw_read_u8(&r, &b));                       // dust_added_to_fee
        mw_skip(&r, e->change_dts.len + e->selected_transfers.len);
        CHECK(mw_read_varint(&r, &v));
        mw_skip(&r, (size_t)v + 32);                     // key_images, tx_key
        CHECK(mw_read_varint(&r, &v) && v == 0);
        mw_skip(&r, e->dests.len + e->cd.len);
        CHECK(mw_read_varint(&r, &v) && v == 0);
        mw_skip(&r, 32);
        CHECK(mw_read_varint(&r, &v) && v == 0);         // key_images vector
        CHECK(mw_read_varint(&r, &v) && v == 2);         // tx_key_images
        int change_ok = 0, nt_ok = 0;
        for (int i = 0; i < 2; ++i) {
            mw_pubkey_t p;
            mw_keyimage_t ki;
            CHECK(mw_read_varint(&r, &v) && v == 2);
            CHECK(mw_read_point(&r, &p) && mw_read_point(&r, &ki));
            if (mw_point_eq(&p, &g_outs[1].one_time)) {
                mw_exported_output_t o;
                mw_exported_key_image_t k;
                memset(&o, 0, sizeof o);
                o.one_time_pubkey = g_outs[1].one_time;
                o.tx_pub_key = g_outs[1].tx_pub;
                o.internal_output_index = g_outs[1].idx;
                CHECK_EQ_INT(mw_key_image_from_output(&g_base, &o, &k), MW_OK);
                CHECK_EQ_MEM(k.image.b, ki.b, 32);
                nt_ok++;
            } else {
                for (uint32_t o = 0; o < tx.n_out; ++o) {
                    if (!mw_point_eq(&p, &tx.out_key[o])) continue;
                    mw_pubkey_t R;
                    mw_seckey_t x;
                    mw_keyimage_t want;
                    memcpy(R.b, tx.extra + 1, 32);
                    CHECK_EQ_INT(mw_output_secret(&g_base, &p, &R, NULL, o, 0, 0, &x), MW_OK);
                    CHECK_EQ_INT(mw_generate_key_image(&p, &x, &want), MW_OK);
                    CHECK_EQ_MEM(want.b, ki.b, 32);
                    change_ok++;
                }
            }
        }
        CHECK_EQ_INT(change_ok, 1);
        CHECK_EQ_INT(nt_ok, 1);
        CHECK_EQ_INT((int)mw_remaining(&r), 0);
    }

    // The cache now knows the inputs as spent and the change as ours (the
    // requested output was already known from the key image export).
    CHECK_EQ_INT(mw_ki_cache_count(), 4 + 1);
    for (uint32_t i = 0; i < 2; ++i) {
        const mw_ki_entry_t* e = mw_ki_cache_find_image(&tx.ki[i]);
        CHECK(e != NULL && (e->flags & MW_KI_F_SPENT));
    }

    // Signing the same inputs again is reported as a re-spend.
    flen = sealed_unsigned(NULL, 0);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_OK);
    CHECK_EQ_INT(rv.spent_before, 2);
}

MW_TEST(test_unsigned_refusals)
{
    mw_tx_review_t rv;
    mw_ops_error_t er;

    // An input whose key image was never synchronised (g_outs[4]).
    make_cd(&g_outs[0], &g_outs[4], 1000000000000ULL);
    size_t flen = sealed_unsigned(NULL, 0);
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_ERR_NOT_SUPPORTED);
    CHECK(strstr(er.text, "not synchronised") != NULL);
    // Without the cache requirement it goes through.
    flen = sealed_unsigned(NULL, 0);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         false, &rv, &er), MW_OK);

    // Change address substitution.
    make_cd(&g_outs[0], &g_outs[1], 1000000000000ULL);
    {
        mw_address_t forged;
        memset(&forged, 0, sizeof forged);
        fx_random_point(&forged.spend);
        mw_point_scalarmult(&forged.view, &g_base.sec.view, &forged.spend);
        forged.type = MW_ADDR_SUBADDRESS;
        const uint64_t amt = g_cd.change.amount;
        fx_dest_from_address(&g_cd.change, &forged, amt);
        g_cd.splitted[1] = g_cd.change;
    }
    flen = sealed_unsigned(NULL, 0);
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_ERR_KEY_MISMATCH);
    CHECK(strstr(er.text, "hybrid") != NULL);

    // A set made by another wallet.
    make_cd(&g_outs[0], &g_outs[1], 1000000000000ULL);
    {
        size_t plen = fx_unsigned_set(&g_cd, 1, NULL, 0, 2, g_plain, sizeof g_plain);
        CHECK_EQ_INT(mw_file_seal(&MW_FILE_UNSIGNED_TX, g_plain, plen, &g_pp, g_file,
                                  sizeof g_file, &flen), MW_OK);
    }
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_ERR_SIGNATURE);

    // An input that is not ours at all.
    {
        mw_account_keys_t other;
        fx_output_t foreign;
        fx_account(&other, 0x42);
        fx_make_output(&other, 0, 0, 0, 1000000000000ULL, 1, &foreign);
        make_cd(&g_outs[0], &foreign, 100);
    }
    flen = sealed_unsigned(NULL, 0);
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess,
                                         true, &rv, &er), MW_ERR_KEY_MISMATCH);
    CHECK(strstr(er.text, "does not belong") != NULL);
}

// ------------------------------------------------- change and own outputs
#define F_FEE 45000000ULL

// Two inputs, no destinations yet; returns what they hold.
static uint64_t cd_begin(const fx_output_t* a, const fx_output_t* b, uint32_t acct)
{
    memset(&g_cd, 0, sizeof g_cd);
    fx_make_source(&g_cd.sources[0], a, 3, 90000);
    fx_make_source(&g_cd.sources[1], b, 12, 95000);
    g_cd.n_sources = 2;
    g_cd.view_tags = 1;
    g_cd.subaddr_account = acct;
    return a->amount + b->amount;
}

static mw_err_t inspect_cd(mw_tx_review_t* rv, mw_ops_error_t* er)
{
    const size_t flen = sealed_unsigned(NULL, 0);
    memset(er, 0, sizeof *er);
    return mw_ops_unsigned_inspect(&g_base, MW_NET_MAINNET, g_file, flen, &g_sess, true,
                                   rv, er);
}

// Signs the inspected set and decodes the transaction it carries.
static void sign_and_decode(fx_tx_t* tx)
{
    mw_ops_error_t er;
    size_t olen = 0, sl = 0;
    memset(&er, 0, sizeof er);
    CHECK_EQ_INT(mw_ops_unsigned_sign(&g_base, &g_sess, g_out, sizeof g_out, &olen, NULL,
                                      &er), MW_OK);
    if (er.text[0]) printf("    sign: %s\n", er.text);
    CHECK_EQ_INT(mw_file_open(&MW_FILE_SIGNED_TX, g_out, olen, &g_base, g_plain,
                              sizeof g_plain, &sl), MW_OK);
    mw_reader_t r;
    uint64_t v = 0;
    mw_reader_init(&r, g_plain, sl);
    CHECK(mw_read_varint(&r, &v) && v == 0);
    CHECK(mw_read_varint(&r, &v) && v == 1);
    CHECK(mw_read_varint(&r, &v) && v == 1);
    CHECK_EQ_INT(fx_decode_tx(g_plain + r.pos, sl - r.pos, tx), 0);
    CHECK_EQ_INT(fx_verify_tx(g_plain + r.pos, tx, g_cd.sources, g_cd.n_sources), 0);
}

// Which own subaddress has spend key D (small range: what the tests use)?
static bool own_index(const mw_point_t* D, uint32_t* M, uint32_t* m)
{
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < 12; ++j) {
            mw_address_t a;
            CHECK_EQ_INT(mw_get_subaddress(&g_base, i, j, &a), MW_OK);
            if (mw_point_eq(&a.spend, D)) {
                *M = i;
                *m = j;
                return true;
            }
        }
    }
    return false;
}

// Decodes output i's amount with `der` and checks it opens outPk.
static bool open_output(const fx_tx_t* t, uint32_t i, const mw_point_t* der, uint64_t* amount)
{
    mw_scalar_t ak, am;
    mw_ecdh_mask_t mask;
    mw_point_t c;
    *amount = 0;
    mw_derivation_to_scalar(der, i, &ak);
    memcpy(amount, t->ecdh[i], 8);
    mw_ecdh_decode(&ak, amount, &mask);
    fx_amount_scalar(*amount, &am);
    mw_commit(&c, &mask, &am);
    return mw_point_eq(&c, &t->out_pk[i]) != 0;
}

// What you see is what you sign: scans every output of the signed tx with
// the device keys and checks it against the review summary.
static void check_wysiwys(const fx_tx_t* t, const mw_tx_summary_t* sum, uint32_t acct)
{
    mw_pubkey_t R, add[MW_MAX_OUTPUTS];
    uint32_t n_add = 0;
    CHECK_EQ_INT(t->extra[0], 0x01);
    memcpy(R.b, t->extra + 1, 32);
    if (t->extra_len > 35 && t->extra[33] == 0x04) {
        n_add = t->extra[34];
        for (uint32_t k = 0; k < n_add && k < MW_MAX_OUTPUTS; ++k)
            memcpy(add[k].b, t->extra + 35 + 32 * k, 32);
    }
    bool used[MW_MAX_DESTINATIONS];
    memset(used, 0, sizeof used);
    uint64_t at_change = 0, own_rows_at_change = 0;
    int dummies = 0, own_outputs = 0, own_rows = 0;
    for (uint8_t r = 0; r < sum->n_recipients; ++r) {
        if (!sum->recipient_own[r]) continue;
        own_rows++;
        if (sum->recipient_major[r] == acct && sum->recipient_minor[r] == 0) {
            own_rows_at_change += sum->amounts[r];
            used[r] = true;
        }
    }
    for (uint32_t i = 0; i < t->n_out; ++i) {
        bool own = false;
        for (int k = 0; k < 2 && !own; ++k) {
            const mw_pubkey_t* key = k == 0 ? &R : (i < n_add ? &add[i] : NULL);
            if (!key) continue;
            mw_point_t der, hG, D;
            mw_scalar_t h;
            CHECK_EQ_INT(mw_generate_key_derivation(key, &g_base.sec.view, &der), MW_OK);
            mw_derivation_to_scalar(&der, i, &h);
            mw_point_scalarmult_base(&hG, &h);
            CHECK_EQ_INT(mw_point_sub(&D, &t->out_key[i], &hG), 0);
            uint32_t M = 0, m = 0;
            if (!own_index(&D, &M, &m)) continue;
            uint64_t amount = 0;
            CHECK(open_output(t, i, &der, &amount));
            own = true;
            own_outputs++;
            if (M == acct && m == 0) {
                at_change += amount;
            } else {
                bool matched = false;
                for (uint8_t r = 0; r < sum->n_recipients && !matched; ++r) {
                    if (used[r] || !sum->recipient_own[r] || sum->recipient_major[r] != M ||
                        sum->recipient_minor[r] != m || sum->amounts[r] != amount) continue;
                    used[r] = matched = true;
                }
                CHECK(matched);
            }
        }
        if (!own) {
            // wallet2's dummy: derivation a*R, amount 0, a foreign key.
            mw_point_t der;
            uint64_t amount = 1;
            CHECK_EQ_INT(mw_generate_key_derivation(&R, &g_base.sec.view, &der), MW_OK);
            if (open_output(t, i, &der, &amount) && amount == 0) dummies++;
        }
    }
    CHECK_EQ_INT((long long)at_change, (long long)(sum->change + own_rows_at_change));
    CHECK_EQ_INT(dummies, sum->n_dummy);
    for (uint8_t r = 0; r < sum->n_recipients; ++r)
        if (sum->recipient_own[r]) CHECK(used[r]);       // no "own" row unfounded
    CHECK_EQ_INT(own_outputs, own_rows + (sum->has_change ? 1 : 0));
}

static fx_output_t g_acc1[2];

// F1: the change shown with its address, main account and account 1.
MW_TEST(test_unsigned_change_display)
{
    static fx_tx_t tx;
    mw_tx_review_t rv;
    mw_ops_error_t er;

    // Account-1 outputs, synchronised through a key image export.
    fx_make_output(&g_base, 0, 1, 3, 1500000000000ULL, 800, &g_acc1[0]);
    fx_make_output(&g_base, 1, 1, 5, 1000000000000ULL, 801, &g_acc1[1]);
    {
        size_t plen = fx_outputs_plain(&g_base, g_acc1, 2, 20, 22, g_plain, sizeof g_plain);
        size_t flen = 0, pl = 0, olen = 0;
        mw_ki_export_info_t info;
        CHECK_EQ_INT(mw_file_seal(&MW_FILE_OUTPUTS, g_plain, plen, &g_base, g_file,
                                  sizeof g_file, &flen), MW_OK);
        memset(&er, 0, sizeof er);
        CHECK_EQ_INT(mw_ops_outputs_inspect(&g_base, g_file, flen, &pl, &info, &er), MW_OK);
        CHECK_EQ_INT(mw_ops_outputs_to_keyimages(&g_base, g_file, pl, g_out, sizeof g_out,
                                                 &olen, NULL, &er), MW_OK);
    }

    const uint64_t in = cd_begin(&g_acc1[0], &g_acc1[1], 1);
    const uint64_t pay = 2000000000000ULL;
    mw_address_t chg;
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 1, 0, &chg), MW_OK);
    chg.type = MW_ADDR_SUBADDRESS;
    fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
    fx_dest_from_address(&g_cd.change, &chg, in - pay - F_FEE);
    g_cd.splitted[1] = g_cd.change;
    g_cd.n_splitted = 2;
    g_cd.subaddr_indices[0] = 3;
    g_cd.subaddr_indices[1] = 5;
    g_cd.n_indices = 2;
    CHECK_EQ_INT(inspect_cd(&rv, &er), MW_OK);
    if (er.text[0]) printf("    inspect: %s\n", er.text);
    const mw_tx_summary_t* s = &rv.sum[0];
    CHECK(s->has_change);
    CHECK_EQ_INT(s->change_addr[0], '8');
    CHECK_EQ_INT((int)s->change_major, 1);
    CHECK_EQ_INT((int)s->change_minor, 0);
    {
        char str[MW_ADDRESS_STR_MAX];
        chg.network = MW_NET_MAINNET;
        CHECK_EQ_INT(mw_address_encode(&chg, str, sizeof str), MW_OK);
        CHECK_EQ_STR(s->change_addr, str);
    }
    CHECK_EQ_INT((long long)s->change, (long long)(in - pay - F_FEE));
    CHECK_EQ_INT(s->n_recipients, 1);
    sign_and_decode(&tx);
    check_wysiwys(&tx, s, 1);
}

// F2/F3: hybrid destinations and claimed-change lies, refused at review and
// by the signer.
MW_TEST(test_unsigned_hybrid_refusals)
{
    mw_tx_review_t rv;
    mw_ops_error_t er;
    mw_address_t h, main_addr;
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 0, &main_addr), MW_OK);

    for (int c = 0; c < 4; ++c) {
        const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
        const uint64_t pay = 1000000000000ULL;
        if (c == 0) fx_hybrid_view(&h, &g_base);          // C4
        else if (c == 1) fx_hybrid_subaddr(&h, &g_base);  // C5
        else if (c == 2) fx_hybrid_spend(&h, &g_base);    // C6
        else fx_hybrid_view(&h, &g_base);                 // C7
        fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
        fx_dest_from_address(&g_cd.splitted[1], &h, in - pay - F_FEE);
        g_cd.n_splitted = 2;
        if (c == 3)          // claims the main address, pays the hybrid
            fx_dest_from_address(&g_cd.change, &main_addr, in - pay - F_FEE);
        CHECK_EQ_INT(inspect_cd(&rv, &er), MW_ERR_KEY_MISMATCH);
        CHECK(strstr(er.text, "hybrid") != NULL);
        CHECK(strlen(er.text) < sizeof er.text - 1);
    }

    // The signer refuses on its own as well (no inspect in between).
    {
        const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
        fx_dest_from_address(&g_cd.splitted[0], &g_recipient, 1000);
        fx_dest_from_address(&g_cd.splitted[1], &main_addr, in - 1000 - F_FEE);
        fx_dest_from_address(&g_cd.change, &main_addr, in - 1000 - F_FEE);
        g_cd.n_splitted = 2;
        CHECK_EQ_INT(inspect_cd(&rv, &er), MW_OK);
        // Same parsed set, but the session tx is reloaded from a tampered set.
        fx_hybrid_view(&h, &g_base);
        fx_dest_from_address(&g_cd.splitted[0], &h, 1000);
        size_t plen = fx_unsigned_set(&g_cd, 1, NULL, 0, 2, g_plain, sizeof g_plain);
        mw_ff_diag_t d;
        memset(&d, 0, sizeof d);
        memcpy(g_file, g_plain, plen);
        CHECK_EQ_INT(mw_unsigned_set_parse(g_file, plen, &g_sess.set, &d), MW_OK);
        size_t olen = 0;
        memset(&er, 0, sizeof er);
        CHECK_EQ_INT(mw_ops_unsigned_sign(&g_base, &g_sess, g_out, sizeof g_out, &olen, NULL,
                                          &er), MW_ERR_KEY_MISMATCH);
        CHECK(strstr(er.text, "hybrid") != NULL);
        CHECK_EQ_INT((int)olen, 0);
    }

    // C8: claimed change ten times what the change address gets.
    {
        const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
        const uint64_t pay = 1000000000000ULL;
        fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
        fx_dest_from_address(&g_cd.splitted[1], &main_addr, in - pay - F_FEE);
        fx_dest_from_address(&g_cd.change, &main_addr, (in - pay - F_FEE) * 10);
        g_cd.n_splitted = 2;
        CHECK_EQ_INT(inspect_cd(&rv, &er), MW_ERR_KEY_MISMATCH);
        CHECK(strstr(er.text, "claimed change") != NULL);
    }
    // C7 with a plain foreign address: the claimed change is not paid.
    {
        mw_address_t other;
        fx_foreign_address(&other);
        const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
        const uint64_t pay = 1000000000000ULL;
        fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
        fx_dest_from_address(&g_cd.splitted[1], &other, in - pay - F_FEE);
        fx_dest_from_address(&g_cd.change, &main_addr, in - pay - F_FEE);
        g_cd.n_splitted = 2;
        CHECK_EQ_INT(inspect_cd(&rv, &er), MW_ERR_KEY_MISMATCH);
        CHECK(strstr(er.text, "claimed change") != NULL);
    }
}

// F4: sweeps make a 0-amount dummy change; it is not a recipient.
MW_TEST(test_unsigned_dummy_and_sweep)
{
    static fx_tx_t tx;
    mw_tx_review_t rv;
    mw_ops_error_t er;
    mw_address_t main_addr, dummy;
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 0, &main_addr), MW_OK);

    for (int self = 0; self < 2; ++self) {
        const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
        fx_foreign_address(&dummy);
        fx_dest_from_address(&g_cd.splitted[0], self ? &main_addr : &g_recipient,
                             in - F_FEE);
        fx_dest_from_address(&g_cd.splitted[1], &dummy, 0);
        fx_dest_from_address(&g_cd.change, &dummy, 0);
        g_cd.n_splitted = 2;
        CHECK_EQ_INT(inspect_cd(&rv, &er), MW_OK);
        if (er.text[0]) printf("    inspect: %s\n", er.text);
        const mw_tx_summary_t* s = &rv.sum[0];
        CHECK_EQ_INT(s->n_dummy, 1);
        CHECK_EQ_INT(s->n_recipients, 1);
        CHECK(!s->has_change);
        CHECK_EQ_INT((int)s->recipient_own[0], self);
        CHECK_EQ_INT((long long)s->total_out, (long long)(in - F_FEE));
        sign_and_decode(&tx);
        check_wysiwys(&tx, s, 0);
    }
}

// F5: own address with a lying flag, inputs outside the account, change to
// an index wallet2 never uses.
MW_TEST(test_unsigned_flag_and_account_lies)
{
    mw_tx_review_t rv;
    mw_ops_error_t er;
    mw_address_t main_addr, a;
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 0, &main_addr), MW_OK);
    const uint64_t pay = 1000000000000ULL;

    // C10: the main address flagged as a subaddress.
    uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
    fx_dest_from_address(&g_cd.splitted[0], &main_addr, pay);
    g_cd.splitted[0].is_sub = 1;
    fx_dest_from_address(&g_cd.splitted[1], &main_addr, in - pay - F_FEE);
    fx_dest_from_address(&g_cd.change, &main_addr, in - pay - F_FEE);
    g_cd.n_splitted = 2;
    CHECK_EQ_INT(inspect_cd(&rv, &er), MW_ERR_KEY_MISMATCH);
    CHECK(strstr(er.text, "subaddress flag") != NULL);

    // C11: subaddr_account 7, change to (7,0), inputs in account 0.
    in = cd_begin(&g_outs[0], &g_outs[1], 7);
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 7, 0, &a), MW_OK);
    a.type = MW_ADDR_SUBADDRESS;
    fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
    fx_dest_from_address(&g_cd.splitted[1], &a, in - pay - F_FEE);
    fx_dest_from_address(&g_cd.change, &a, in - pay - F_FEE);
    g_cd.n_splitted = 2;
    CHECK(inspect_cd(&rv, &er) != MW_OK);
    CHECK(strstr(er.text, "account") != NULL);

    // C12: change to (0, 1000000) named by a subaddr_indices hint.
    in = cd_begin(&g_outs[0], &g_outs[1], 0);
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 1000000, &a), MW_OK);
    a.type = MW_ADDR_SUBADDRESS;
    fx_dest_from_address(&g_cd.splitted[0], &g_recipient, pay);
    fx_dest_from_address(&g_cd.splitted[1], &a, in - pay - F_FEE);
    fx_dest_from_address(&g_cd.change, &a, in - pay - F_FEE);
    g_cd.n_splitted = 2;
    g_cd.subaddr_indices[0] = 1000000;
    g_cd.n_indices = 1;
    CHECK_EQ_INT(inspect_cd(&rv, &er), MW_ERR_KEY_MISMATCH);
    CHECK(strstr(er.text, "refused") != NULL);
}

// F6: what the review and the signer log never contains.
static char g_logbuf[16384];
static size_t g_loglen;

static void log_capture(mw_log_level_t level, const char* line, void* ctx)
{
    (void)level;
    (void)ctx;
    const size_t n = strlen(line);
    if (g_loglen + n + 2 < sizeof g_logbuf) {
        memcpy(g_logbuf + g_loglen, line, n);
        g_loglen += n;
        g_logbuf[g_loglen++] = '\n';
        g_logbuf[g_loglen] = 0;
    }
}

static void hex32(const uint8_t* b, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2 * i] = hexd[b[i] >> 4];
        out[2 * i + 1] = hexd[b[i] & 15];
    }
    out[64] = 0;
}

MW_TEST(test_unsigned_log_hygiene)
{
    static fx_tx_t tx;
    mw_tx_review_t rv;
    mw_ops_error_t er;
    mw_address_t main_addr, own4;
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 0, &main_addr), MW_OK);
    CHECK_EQ_INT(mw_get_subaddress(&g_base, 0, 4, &own4), MW_OK);
    own4.type = MW_ADDR_SUBADDRESS;

    g_loglen = 0;
    g_logbuf[0] = 0;
    mw_log_init();
    mw_log_set_debug(true);
    mw_log_set_sink(log_capture, NULL);
    const uint64_t in = cd_begin(&g_outs[0], &g_outs[1], 0);
    const uint64_t pay = 1000000000000ULL;
    fx_dest_from_address(&g_cd.splitted[0], &own4, pay);
    fx_dest_from_address(&g_cd.splitted[1], &main_addr, in - pay - F_FEE);
    fx_dest_from_address(&g_cd.change, &main_addr, in - pay - F_FEE);
    g_cd.n_splitted = 2;
    CHECK_EQ_INT(inspect_cd(&rv, &er), MW_OK);
    CHECK(rv.sum[0].recipient_own[0]);
    sign_and_decode(&tx);
    check_wysiwys(&tx, &rv.sum[0], 0);
    mw_log_set_sink(NULL, NULL);
    mw_log_set_debug(false);

    char hex[65];
    CHECK(strstr(g_logbuf, "-> this wallet 0/0 (re-derived)") != NULL);
    CHECK(strstr(g_logbuf, "own address 0/4") != NULL);
    hex32(g_base.sec.view.b, hex);
    CHECK(strstr(g_logbuf, hex) == NULL);
    hex32(g_base.sec.spend.b, hex);
    CHECK(strstr(g_logbuf, hex) == NULL);
    hex32(g_base.pub.view.b, hex);
    CHECK(strstr(g_logbuf, hex) == NULL);
    // No full addresses either.
    CHECK(strstr(g_logbuf, rv.sum[0].change_addr) == NULL);
    CHECK(strstr(g_logbuf, rv.sum[0].recipients[0]) == NULL);
}

// ------------------------------------------------------------ export
MW_TEST(test_wallet_export)
{
    char json[512], hex[65];
    size_t len = 0;
    CHECK_EQ_INT(mw_ops_wallet_export(&g_base, MW_NET_MAINNET, "bo\"rya", 3100000, false,
                                      json, sizeof json, &len), MW_OK);
    CHECK_EQ_INT((int)strlen(json), (int)len);
    CHECK(strstr(json, "\"address\": \"4") != NULL);
    CHECK(strstr(json, "bo\\\"rya") != NULL);
    CHECK(strstr(json, "\"restore_height\": 3100000") != NULL);
    CHECK(strstr(json, "view_key") == NULL);

    CHECK_EQ_INT(mw_ops_wallet_export(&g_base, MW_NET_STAGENET, "b", 0, true, json,
                                      sizeof json, &len), MW_OK);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex[2 * i] = hexd[g_base.sec.view.b[i] >> 4];
        hex[2 * i + 1] = hexd[g_base.sec.view.b[i] & 15];
    }
    hex[64] = 0;
    CHECK(strstr(json, hex) != NULL);
    CHECK(strstr(json, "\"network\": \"stagenet\"") != NULL);
    // The spend key never leaves the device.
    for (int i = 0; i < 32; ++i) {
        hex[2 * i] = hexd[g_base.sec.spend.b[i] >> 4];
        hex[2 * i + 1] = hexd[g_base.sec.spend.b[i] & 15];
    }
    CHECK(strstr(json, hex) == NULL);
    CHECK(mw_ops_wallet_export(&g_base, MW_NET_MAINNET, "b", 0, true, json, 64, &len) != MW_OK);
}

// Audit round 1: an older copy of the cache file put back is refused, and a
// full cache says so instead of dropping entries silently.
static uint8_t g_snap[256 * 1024];
MW_TEST(test_ki_cache_rollback_and_full)
{
    char name[40];
    size_t size = 0, got = 0;
    mw_ki_entry_t e;
    snprintf(name, sizeof name, "ki_%08lx_0.bin", (unsigned long)g_id);

    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK(!mw_ki_cache_rolled_back());
    const uint32_t n0 = mw_ki_cache_count();
    CHECK(n0 > 0);
    // Snapshot the current file, then mark something spent and save.
    memset(&e, 0, sizeof e);
    memset(e.out_pub.b, 0xA1, 32);
    memset(e.image.b, 0xB2, 32);
    e.flags = MW_KI_F_SPENT;
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    CHECK_EQ_INT(mw_fstore_size(name, &size), MW_OK);
    CHECK(size <= sizeof g_snap);
    CHECK_EQ_INT(mw_fstore_read(name, g_snap, size, &got), MW_OK);
    const size_t snap_len = got;
    memset(e.out_pub.b, 0xA2, 32);
    memset(e.image.b, 0xB3, 32);
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    mw_ki_cache_close();

    // The newer file opens normally.
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK(!mw_ki_cache_rolled_back());
    CHECK_EQ_INT(mw_ki_cache_count(), n0 + 2);
    mw_ki_cache_close();

    // The old copy put back: refused, cache empty, flagged.
    CHECK_EQ_INT(mw_fstore_write(name, g_snap, snap_len), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK(mw_ki_cache_rolled_back());
    CHECK_EQ_INT(mw_ki_cache_count(), 0);
    // Saving afterwards moves past both generations.
    memset(e.out_pub.b, 0xA3, 32);
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    CHECK(!mw_ki_cache_rolled_back());
    mw_ki_cache_close();
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK(!mw_ki_cache_rolled_back());
    CHECK_EQ_INT(mw_ki_cache_count(), 1);

    // Fill it up: the insert that does not fit is reported, nothing evicted.
    for (uint32_t i = mw_ki_cache_count(); i < MW_KI_CACHE_MAX; ++i) {
        memset(&e, 0, sizeof e);
        e.out_pub.b[0] = (uint8_t)i; e.out_pub.b[1] = (uint8_t)(i >> 8); e.out_pub.b[2] = 0xEE;
        e.image.b[0] = (uint8_t)i;   e.image.b[1] = (uint8_t)(i >> 8);   e.image.b[2] = 0xEE;
        CHECK_EQ_INT(mw_ki_cache_put(&e), MW_OK);
    }
    CHECK_EQ_INT(mw_ki_cache_count(), MW_KI_CACHE_MAX);
    memset(e.out_pub.b, 0xCC, 32);
    CHECK_EQ_INT(mw_ki_cache_put(&e), MW_ERR_TOO_MANY);
    CHECK_EQ_INT(mw_ki_cache_count(), MW_KI_CACHE_MAX);
    mw_ki_cache_close();                    // not saved
    // Leave the cache open with the saved file, as the next test expects.
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_count(), 1);
}

MW_TEST(test_delete_wipes_cache)
{
    CHECK_EQ_INT(mw_ki_cache_save(), MW_OK);
    const uint32_t n = mw_ki_cache_count();
    CHECK(n > 0);
    mw_ki_cache_close();

    // A device password change re-seals the cache with the wallets.
    {
        uint8_t nk[32];
        memset(nk, 0x6b, sizeof nk);
        CHECK_EQ_INT(mw_wallet_store_rekey(USER_KEY, nk), MW_OK);
        CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
        CHECK_EQ_INT(mw_ki_cache_count(), n);
        mw_ki_cache_close();
        CHECK_EQ_INT(mw_wallet_store_rekey(nk, USER_KEY), MW_OK);
        CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
        CHECK_EQ_INT(mw_ki_cache_count(), n);
        mw_ki_cache_close();
    }

    CHECK_EQ_INT(mw_wallet_delete(g_id), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_open(g_id, 0, &g_base), MW_OK);
    CHECK_EQ_INT(mw_ki_cache_count(), 0);
    mw_ki_cache_close();
    mw_host_store_reset();
}

int main(void)
{
    mw_random_init();
    CHECK_EQ_INT(mw_bpp_init(), MW_OK);

    RUN_TEST(test_two_wallets_per_seed);
    RUN_TEST(test_outputs_to_key_images);
    RUN_TEST(test_unsigned_to_signed);
    RUN_TEST(test_unsigned_refusals);
    RUN_TEST(test_unsigned_change_display);
    RUN_TEST(test_unsigned_hybrid_refusals);
    RUN_TEST(test_unsigned_dummy_and_sweep);
    RUN_TEST(test_unsigned_flag_and_account_lies);
    RUN_TEST(test_unsigned_log_hygiene);
    RUN_TEST(test_wallet_export);
    RUN_TEST(test_ki_cache_rollback_and_full);
    RUN_TEST(test_delete_wipes_cache);

    mw_bpp_free();
    return mw_test_summary();
}
