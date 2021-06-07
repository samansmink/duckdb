//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/file_buffer.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "crypto_stream.h"
#include "crypto_stream_aes128ctr.h"
#include "crypto_stream_salsa208.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_xsalsa20.h"
#include "duckdb/common/constants.hpp"
#include "duckdb/common/types/hash.hpp"
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

extern "C" {
#include "chacha.h"
};

namespace duckdb {

#define NONCE_BYTES crypto_stream_NONCEBYTES // For all NACL functions
//#define NONCE_BYTES 16 // For OPENSSL AES CTR

int aes_ctr_128_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                        unsigned char *ciphertext);
int aes_ctr_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
                        unsigned char *plaintext);

inline void chacha8avx_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv,
                               unsigned char *ciphertext) {
	ECRYPT_ctx x;
	ECRYPT_keysetup(&x, (unsigned char *)TEST_KEY, 256, 0);
	ECRYPT_ivsetup(&x, iv);
	ECRYPT_encrypt_bytes(&x, plaintext, ciphertext, plaintext_len);
}

inline void chacha8avx_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
                               unsigned char *plaintext) {
	ECRYPT_ctx x;
	ECRYPT_keysetup(&x, key, 256, 0);
	ECRYPT_ivsetup(&x, iv);
	ECRYPT_decrypt_bytes(&x, ciphertext, plaintext, ciphertext_len);
}

inline void chacha8avx_decrypt_offset(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                                      unsigned char *iv, unsigned char *plaintext, unsigned int offset_blocks) {
	ECRYPT_ctx x;
	ECRYPT_keysetup(&x, key, 256, 0);
	ECRYPT_ivsetup(&x, iv);
	x.input[12] = offset_blocks;
	ECRYPT_decrypt_bytes(&x, ciphertext, plaintext, ciphertext_len);
}

inline void Encrypt(unsigned char *ciphertext, unsigned char *plaintext, long length, unsigned char *nonce) {
	memcpy(nonce, (unsigned char *)TEST_NONCE, NONCE_BYTES);

    crypto_stream_salsa20_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_salsa208_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_xsalsa20_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_aes128ctr_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    aes_ctr_128_encrypt(plaintext, length, (unsigned char *)TEST_KEY, nonce, ciphertext);
//    chacha8avx_encrypt(plaintext, length, (unsigned char *)TEST_KEY, nonce, ciphertext);
//    memcpy(ciphertext, plaintext, length);
}

inline void Decrypt(unsigned char *plaintext, unsigned char *ciphertext, long length, unsigned char *nonce) {
    crypto_stream_salsa20_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_salsa208_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_xsalsa20_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_aes128ctr_xor(ciphertext, plaintext, length, nonce, (unsigned char *)TEST_KEY);
//    aes_ctr_128_decrypt(ciphertext, length, (unsigned char*)TEST_KEY, nonce, plaintext);
//    chacha8avx_decrypt(ciphertext, length, (unsigned char *)TEST_KEY, nonce, plaintext);
//    memcpy(plaintext, ciphertext, length);
}

inline void DecryptAtOffset(unsigned char *plaintext, unsigned char *ciphertext, long length, unsigned char *nonce,
                            unsigned int offset_blocks) {
//    crypto_stream_salsa208_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_xsalsa20_xor(ciphertext, plaintext, length, nonce, (unsigned char*)TEST_KEY);
//    crypto_stream_aes128ctr_xor(ciphertext, plaintext, length, nonce, (unsigned char *)TEST_KEY);
//    aes_ctr_128_decrypt(ciphertext, length, (unsigned char*)TEST_KEY, nonce, plaintext);
//    chacha8avx_decrypt_offset(ciphertext, length, (unsigned char *)TEST_KEY, nonce, plaintext, offset_blocks);
    memcpy(plaintext, ciphertext, length);
} // namespace duckdb
}