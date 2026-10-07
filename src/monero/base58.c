// Monero-flavoured Base58 (TZ 6.5).
//
// Unlike Bitcoin's, Monero's Base58 works on fixed 8-byte blocks: every full
// block becomes exactly 11 characters and the trailing partial block uses the
// size table below. This keeps encoding O(n) and makes the address length
// constant.
#include "address.h"

#include <string.h>
#include <stdint.h>

#include "../crypto/hash.h"

static const char b58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define B58_ALPHABET_SIZE 58
#define FULL_BLOCK_SIZE          8
#define FULL_ENCODED_BLOCK_SIZE 11

// encoded_block_sizes[decoded bytes] -> encoded characters
static const uint8_t encoded_block_sizes[FULL_BLOCK_SIZE + 1] = {
    0, 2, 3, 5, 6, 7, 9, 10, 11
};

// Reverse of the table above; 0xFF marks an impossible encoded size.
static int decoded_block_size(size_t enc_size)
{
    for (int i = 0; i <= FULL_BLOCK_SIZE; ++i) {
        if (encoded_block_sizes[i] == enc_size) {
            return i;
        }
    }
    return -1;
}

static int b58_digit(char c)
{
    for (int i = 0; i < B58_ALPHABET_SIZE; ++i) {
        if (b58_alphabet[i] == c) {
            return i;
        }
    }
    return -1;
}

static uint64_t uint_be_to_64(const uint8_t* data, size_t size)
{
    uint64_t res = 0;
    for (size_t i = 0; i < size; ++i) {
        res = (res << 8) | data[i];
    }
    return res;
}

static void uint_64_to_be(uint64_t num, uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        data[size - 1 - i] = (uint8_t)(num & 0xff);
        num >>= 8;
    }
}

static void encode_block(const uint8_t* block, size_t size, char* out)
{
    size_t enc_size = encoded_block_sizes[size];
    for (size_t i = 0; i < enc_size; ++i) {
        out[i] = b58_alphabet[0];
    }
    uint64_t num = uint_be_to_64(block, size);
    size_t i = enc_size;
    while (num > 0) {
        out[--i] = b58_alphabet[num % B58_ALPHABET_SIZE];
        num /= B58_ALPHABET_SIZE;
    }
}

static mw_err_t decode_block(const char* block, size_t enc_size, uint8_t* out,
                             size_t* dec_size_out)
{
    int dec_size = decoded_block_size(enc_size);
    if (dec_size <= 0) {
        return MW_ERR_FORMAT;
    }

    uint64_t num = 0;
    for (size_t i = 0; i < enc_size; ++i) {
        int digit = b58_digit(block[i]);
        if (digit < 0) {
            return MW_ERR_FORMAT;
        }
        // Exact overflow test: num*58 + digit must stay below 2^64.
        if (num > (UINT64_MAX - (uint64_t)digit) / B58_ALPHABET_SIZE) {
            return MW_ERR_FORMAT;
        }
        num = num * B58_ALPHABET_SIZE + (uint64_t)digit;
    }

    // The value must fit into `dec_size` bytes.
    if (dec_size < 8 && (num >> (8 * dec_size)) != 0) {
        return MW_ERR_FORMAT;
    }

    uint_64_to_be(num, out, (size_t)dec_size);
    *dec_size_out = (size_t)dec_size;
    return MW_OK;
}

size_t mw_base58_encode(const uint8_t* data, size_t len, char* out, size_t out_len)
{
    if (data == NULL || out == NULL || out_len == 0) {
        return 0;
    }

    size_t full_blocks = len / FULL_BLOCK_SIZE;
    size_t rem         = len % FULL_BLOCK_SIZE;
    size_t enc_len     = full_blocks * FULL_ENCODED_BLOCK_SIZE + encoded_block_sizes[rem];

    if (enc_len + 1 > out_len) {
        return 0;
    }

    size_t pos = 0;
    for (size_t i = 0; i < full_blocks; ++i) {
        encode_block(data + i * FULL_BLOCK_SIZE, FULL_BLOCK_SIZE, out + pos);
        pos += FULL_ENCODED_BLOCK_SIZE;
    }
    if (rem > 0) {
        encode_block(data + full_blocks * FULL_BLOCK_SIZE, rem, out + pos);
        pos += encoded_block_sizes[rem];
    }
    out[pos] = '\0';
    return pos;
}

mw_err_t mw_base58_decode(const char* str, uint8_t* out, size_t out_len,
                          size_t* out_written)
{
    if (str == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    size_t enc_len = strlen(str);
    if (enc_len == 0) {
        if (out_written) *out_written = 0;
        return MW_OK;
    }

    size_t full_blocks = enc_len / FULL_ENCODED_BLOCK_SIZE;
    size_t rem_enc     = enc_len % FULL_ENCODED_BLOCK_SIZE;
    int    rem_dec     = rem_enc == 0 ? 0 : decoded_block_size(rem_enc);
    if (rem_dec < 0) {
        return MW_ERR_FORMAT;
    }

    size_t dec_len = full_blocks * FULL_BLOCK_SIZE + (size_t)rem_dec;
    if (dec_len > out_len) {
        return MW_ERR_RANGE;
    }

    size_t pos = 0;
    for (size_t i = 0; i < full_blocks; ++i) {
        size_t written = 0;
        mw_err_t err = decode_block(str + i * FULL_ENCODED_BLOCK_SIZE,
                                    FULL_ENCODED_BLOCK_SIZE, out + pos, &written);
        if (err != MW_OK) {
            return err;
        }
        pos += written;
    }
    if (rem_enc > 0) {
        size_t written = 0;
        mw_err_t err = decode_block(str + full_blocks * FULL_ENCODED_BLOCK_SIZE,
                                    rem_enc, out + pos, &written);
        if (err != MW_OK) {
            return err;
        }
        pos += written;
    }

    if (out_written) {
        *out_written = pos;
    }
    return MW_OK;
}

size_t mw_base58_encode_check(const uint8_t* data, size_t len, char* out,
                              size_t out_len)
{
    if (data == NULL || out == NULL || len > 128) {
        return 0;
    }

    uint8_t buf[132];
    memcpy(buf, data, len);

    uint8_t hash[MW_KECCAK_DIGEST];
    mw_keccak256(data, len, hash);
    memcpy(buf + len, hash, 4);

    return mw_base58_encode(buf, len + 4, out, out_len);
}

mw_err_t mw_base58_decode_check(const char* str, uint8_t* out, size_t out_len,
                                size_t* out_written)
{
    if (str == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }

    uint8_t buf[132];
    size_t written = 0;
    mw_err_t err = mw_base58_decode(str, buf, sizeof(buf), &written);
    if (err != MW_OK) {
        return err;
    }
    if (written < 5) {
        return MW_ERR_FORMAT;
    }

    size_t payload = written - 4;
    uint8_t hash[MW_KECCAK_DIGEST];
    mw_keccak256(buf, payload, hash);
    if (memcmp(hash, buf + payload, 4) != 0) {
        return MW_ERR_CHECKSUM;
    }

    if (payload > out_len) {
        return MW_ERR_RANGE;
    }
    memcpy(out, buf, payload);
    if (out_written) {
        *out_written = payload;
    }
    return MW_OK;
}
