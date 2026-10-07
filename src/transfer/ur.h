// Uniform Resources (Blockchain Commons) - animated QR transport (TZ 3.7).
// Implements bytewords(minimal), CBOR wrapping, and the fountain (multi-part)
// encoder/decoder used by Feather and ANON/NERO.
#ifndef MW_UR_H
#define MW_UR_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_UR_MAX_FRAGMENT     200     // bytes per fragment before bytewords
#define MW_UR_DEFAULT_FRAGMENT 50      // TZ 3.7
#define MW_UR_MAX_PARTS        512
#define MW_UR_TYPE_BYTES       "bytes"
#define MW_UR_TYPE_KEYIMAGE    "crypto-keyimage"

// ---------------- encoder --------------------------------------------------
typedef struct mw_ur_encoder mw_ur_encoder;

mw_ur_encoder* mw_ur_encoder_new(const char* ur_type, const uint8_t* payload,
                                 size_t len, size_t max_fragment);
void           mw_ur_encoder_free(mw_ur_encoder* e);
// Writes the next "ur:bytes/1-7/lpamchcf..." string. Cycles forever.
size_t         mw_ur_encoder_next(mw_ur_encoder* e, char* out, size_t out_cap);
uint32_t       mw_ur_encoder_seq_len(const mw_ur_encoder* e);
bool           mw_ur_encoder_is_single_part(const mw_ur_encoder* e);

// ---------------- decoder --------------------------------------------------
typedef struct mw_ur_decoder mw_ur_decoder;

mw_ur_decoder* mw_ur_decoder_new(uint8_t* buffer, size_t buffer_cap);
void           mw_ur_decoder_free(mw_ur_decoder* d);
// Feeds one scanned QR string. Returns MW_OK on accept, MW_ERR_FORMAT on junk.
mw_err_t       mw_ur_decoder_receive(mw_ur_decoder* d, const char* part);
bool           mw_ur_decoder_complete(const mw_ur_decoder* d);
int            mw_ur_decoder_progress_permille(const mw_ur_decoder* d);
mw_err_t       mw_ur_decoder_result(mw_ur_decoder* d, const uint8_t** data,
                                    size_t* len, char* type_out, size_t type_cap);

// ---------------- bytewords ------------------------------------------------
size_t   mw_bytewords_encode_minimal(const uint8_t* in, size_t len,
                                     char* out, size_t out_cap);
mw_err_t mw_bytewords_decode_minimal(const char* in, uint8_t* out, size_t out_cap,
                                     size_t* out_len);
uint32_t mw_ur_crc32(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif
#endif
