// Key images and the outputs.bin -> keyimages.bin pipeline (TZ 11).
//
// Everything here mirrors monero-project/monero:
//   crypto::generate_key_image()          -> mw_generate_key_image()
//   crypto::generate_ring_signature()     -> mw_generate_key_image_signature()
//   crypto::check_ring_signature()        -> mw_check_key_image_signature()
//   cryptonote::generate_key_image_helper_precomp()
//                                         -> mw_key_image_from_output()
//
// wallet2::import_key_images() verifies the exported signature as a ring
// signature over the single-member ring {P} with the key image as both the
// image and the "prefix hash", so that is exactly what we produce here.
#include "key_image.h"

#include <string.h>

#include "keys.h"
#include "file_formats.h"      // MW_MAX_EXPORTED_OUTPUTS (TZ 11.3 cap)
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"

// ------------------------------------------------------------- key image
mw_err_t mw_generate_key_image(const mw_pubkey_t* pub, const mw_seckey_t* sec,
                               mw_keyimage_t* out)
{
    if (pub == NULL || sec == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(sec)) {
        return MW_ERR_INVALID_ARG;
    }

    // TZ 8.3: never sign with a secret that does not match the public key.
    mw_err_t err = mw_check_key_pair(sec, pub);
    if (err != MW_OK) {
        return err;
    }

    mw_ge_p3 hp;
    mw_hash_to_ec(pub->b, 32, &hp);              // Hp(P)

    mw_ge_p3 image;
    mw_ge_scalarmult(&image, sec, &hp);          // I = x*Hp(P), constant time
    mw_ge_p3_tobytes(out, &image);

    mw_memzero(&image, sizeof(image));
    return MW_OK;
}

// Layout of crypto's rs_comm for a single-member ring:
//     hash     prefix[32]
//     ec_point a[32]        (k*G)
//     ec_point b[32]        (k*Hp(P))
#define RS_COMM_LEN 96

mw_err_t mw_generate_key_image_signature(const mw_pubkey_t* pub,
                                         const mw_seckey_t* sec,
                                         const mw_keyimage_t* image,
                                         mw_ring_sig_t* sig_out)
{
    if (pub == NULL || sec == NULL || image == NULL || sig_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(sec)) {
        return MW_ERR_INVALID_ARG;
    }
    mw_err_t err = mw_check_key_pair(sec, pub);
    if (err != MW_OK) {
        return err;
    }

    uint8_t buf[RS_COMM_LEN];
    memcpy(buf, image->b, 32);                   // prefix hash == the image

    // Hedged nonce (TZ 8.2): TRNG entropy folded with a deterministic context
    // so a stuck RNG cannot leak the secret key.
    uint8_t ctx[32 + 32 + 32];
    memcpy(ctx, pub->b, 32);
    memcpy(ctx + 32, image->b, 32);
    memcpy(ctx + 64, sec->b, 32);
    mw_scalar_t k;
    mw_random_hedged_scalar(&k, ctx, sizeof(ctx));
    mw_memzero(ctx, sizeof(ctx));

    mw_ge_p3 kg;
    mw_ge_scalarmult_base(&kg, &k);
    mw_point_t tmp;
    mw_ge_p3_tobytes(&tmp, &kg);
    memcpy(buf + 32, tmp.b, 32);                 // a = k*G

    mw_ge_p3 hp;
    mw_hash_to_ec(pub->b, 32, &hp);
    mw_ge_p3 khp;
    mw_ge_scalarmult(&khp, &k, &hp);
    mw_ge_p3_tobytes(&tmp, &khp);
    memcpy(buf + 64, tmp.b, 32);                 // b = k*Hp(P)

    // Single member ring: sum of the decoy challenges is zero, so c == h.
    mw_hash_to_scalar(buf, sizeof(buf), &sig_out->c);
    // r = k - c*x
    mw_sc_mulsub(&sig_out->r, &sig_out->c, sec, &k);

    mw_memzero(&k, sizeof(k));
    mw_memzero(&kg, sizeof(kg));
    mw_memzero(&khp, sizeof(khp));
    mw_memzero(buf, sizeof(buf));

    if (mw_sc_is_zero(&sig_out->c) || mw_sc_is_zero(&sig_out->r)) {
        return MW_ERR_SIGNATURE;                 // astronomically unlikely
    }
    return MW_OK;
}

mw_err_t mw_check_key_image_signature(const mw_pubkey_t* pub,
                                      const mw_keyimage_t* image,
                                      const mw_ring_sig_t* sig)
{
    if (pub == NULL || image == NULL || sig == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (!mw_sc_check(&sig->c) || !mw_sc_check(&sig->r)) {
        return MW_ERR_SIGNATURE;
    }
    if (!mw_point_check_public(pub) || !mw_point_check_public(image)) {
        return MW_ERR_SUBGROUP;
    }

    mw_ge_p3 p3_pub;
    if (mw_ge_frombytes_vartime(&p3_pub, pub) != 0) {
        return MW_ERR_FORMAT;
    }
    mw_ge_p3 p3_image;
    if (mw_ge_frombytes_vartime(&p3_image, image) != 0) {
        return MW_ERR_FORMAT;
    }

    uint8_t buf[RS_COMM_LEN];
    memcpy(buf, image->b, 32);

    // a = r*G + c*P
    mw_ge_p2 a;
    mw_ge_double_scalarmult_base_vartime(&a, &sig->c, &p3_pub, &sig->r);
    mw_point_t tmp;
    mw_ge_p2_tobytes(&tmp, &a);
    memcpy(buf + 32, tmp.b, 32);

    // b = r*Hp(P) + c*I
    mw_ge_p3 hp;
    mw_hash_to_ec(pub->b, 32, &hp);
    mw_ge_p2 b;
    mw_ge_double_scalarmult_vartime(&b, &sig->r, &hp, &sig->c, &p3_image);
    mw_ge_p2_tobytes(&tmp, &b);
    memcpy(buf + 64, tmp.b, 32);

    mw_scalar_t h;
    mw_hash_to_scalar(buf, sizeof(buf), &h);
    mw_scalar_t diff;
    mw_sc_sub(&diff, &h, &sig->c);
    return mw_sc_is_zero(&diff) ? MW_OK : MW_ERR_SIGNATURE;
}

// ------------------------------------------ outputs.bin record -> key image
//
// Reconstructs the one-time secret key of an exported output:
//
//     D   = 8 * a * R                     (R = tx pub key, or the additional
//                                          tx pub key when the output was sent
//                                          to one of our subaddresses)
//     x   = Hs(D || output_index) + b     (+ m for subaddress outputs, where
//                                          m = Hs("SubAddr" || a || maj|min))
//     I   = x * Hp(P)
//
// We try the main tx public key first and fall back to the additional key for
// the output's own index, exactly like is_out_to_acc_precomp() does, and we
// accept a candidate only when x*G == P.
static mw_err_t try_derivation(const mw_account_keys_t* keys,
                               const mw_pubkey_t* one_time_pub,
                               const mw_pubkey_t* tx_pub,
                               uint32_t output_index, uint32_t major,
                               uint32_t minor, mw_seckey_t* sec_out)
{
    mw_point_t derivation;
    mw_err_t err = mw_generate_key_derivation(tx_pub, &keys->sec.view, &derivation);
    if (err != MW_OK) {
        return err;
    }

    mw_seckey_t x;
    mw_derive_secret_key(&derivation, output_index, &keys->sec.spend, &x);

    if (major != 0 || minor != 0) {
        mw_scalar_t m;
        mw_get_subaddress_secret_key(&keys->sec.view, major, minor, &m);
        mw_sc_add(&x, &x, &m);
        mw_memzero(&m, sizeof(m));
    }

    err = mw_check_key_pair(&x, one_time_pub);
    if (err != MW_OK) {
        mw_memzero(&x, sizeof(x));
        mw_memzero(&derivation, sizeof(derivation));
        return err;
    }

    *sec_out = x;
    mw_memzero(&x, sizeof(x));
    mw_memzero(&derivation, sizeof(derivation));
    return MW_OK;
}

mw_err_t mw_output_secret(const mw_account_keys_t* keys,
                          const mw_pubkey_t* one_time_pub,
                          const mw_pubkey_t* tx_pub,
                          const mw_pubkey_t* additional_pub,
                          uint32_t output_index, uint32_t major, uint32_t minor,
                          mw_seckey_t* x_out)
{
    if (keys == NULL || one_time_pub == NULL || tx_pub == NULL || x_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (keys->view_only) {
        return MW_ERR_NOT_SUPPORTED;             // needs the spend secret
    }
    // TZ 8.3: every point that came out of a file is validated before use.
    if (!mw_point_check_public(tx_pub) || !mw_point_check_public(one_time_pub)) {
        return MW_ERR_SUBGROUP;
    }
    mw_err_t err = try_derivation(keys, one_time_pub, tx_pub, output_index,
                                  major, minor, x_out);
    if (err != MW_OK && additional_pub != NULL) {
        if (!mw_point_check_public(additional_pub)) {
            return MW_ERR_SUBGROUP;
        }
        err = try_derivation(keys, one_time_pub, additional_pub, output_index,
                             major, minor, x_out);
    }
    if (err != MW_OK) {
        mw_memzero(x_out, sizeof(*x_out));
    }
    return err;
}

mw_err_t mw_key_image_from_output(const mw_account_keys_t* keys,
                                  const mw_exported_output_t* out,
                                  mw_exported_key_image_t* ki_out)
{
    if (keys == NULL || out == NULL || ki_out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (keys->view_only) {
        return MW_ERR_NOT_SUPPORTED;             // needs the spend secret
    }

    memset(ki_out, 0, sizeof(*ki_out));

    mw_seckey_t x;
    mw_err_t err = mw_output_secret(keys, &out->one_time_pubkey, &out->tx_pub_key,
                                    out->has_additional ? &out->additional_tx_pub : NULL,
                                    out->internal_output_index, out->subaddr_major,
                                    out->subaddr_minor, &x);
    if (err != MW_OK) {
        mw_memzero(&x, sizeof(x));
        return err;
    }

    err = mw_generate_key_image(&out->one_time_pubkey, &x, &ki_out->image);
    if (err == MW_OK) {
        err = mw_generate_key_image_signature(&out->one_time_pubkey, &x,
                                              &ki_out->image, &ki_out->sig);
    }
    if (err == MW_OK) {
        // Fault-injection defence: verify what we just produced.
        err = mw_check_key_image_signature(&out->one_time_pubkey, &ki_out->image,
                                           &ki_out->sig);
    }

    mw_memzero(&x, sizeof(x));
    if (err != MW_OK) {
        mw_memzero(ki_out, sizeof(*ki_out));
    }
    return err;
}

// ------------------------------------------------------------------ batch
// TZ 11.3: one bad record (a key that is not ours, a corrupted point, an
// output whose derivation does not reproduce P) must not cost the user the
// whole export. Every record is attempted, failures are recorded, and the
// progress callback drives the UI.
//
// The images of failed records are left zeroed; the caller pairs
// images_out[i] with outputs[i] by index and skips the indices listed in
// `result->failures`.
mw_err_t mw_key_image_batch(const mw_account_keys_t* keys,
                            const mw_exported_output_t* outputs, uint32_t count,
                            mw_exported_key_image_t* images_out,
                            mw_ki_batch_result_t* result,
                            mw_ki_progress_cb cb, void* user)
{
    if (keys == NULL || outputs == NULL || images_out == NULL || result == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (count > MW_MAX_EXPORTED_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }

    result->processed = 0;
    result->failed = 0;

    mw_err_t last_err = MW_OK;
    for (uint32_t i = 0; i < count; ++i) {
        // (see key_image.h: the firmware aborts on the first failure instead)
        memset(&images_out[i], 0, sizeof(images_out[i]));
        mw_err_t err = mw_key_image_from_output(keys, &outputs[i], &images_out[i]);
        if (err == MW_OK) {
            ++result->processed;
        } else {
            last_err = err;
            // Keep counting past the cap so the UI can say "37 of 1000 failed"
            // even when only the first few fit in the caller's buffer.
            if (result->failures != NULL && result->failed < result->failures_cap) {
                result->failures[result->failed].index = i;
                result->failures[result->failed].err = err;
            }
            ++result->failed;
        }
        if (cb != NULL) {
            cb(i + 1u, count, user);
        }
    }

    if (result->processed != 0) {
        return MW_OK;
    }
    return (count == 0) ? MW_OK : last_err;
}
