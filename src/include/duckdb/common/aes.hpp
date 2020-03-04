//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/aes.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

// Max sizes, useful for buffer sizes
#define TAG_SIZE 16
#define TAG_SIZE_ENCODED 25

#include <cstring>

namespace duckdb {

typedef unsigned char aes_tag_t[TAG_SIZE];

class AES {
public:
	AES();

	void HandleErrors();

    inline int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *tag) {
        return GCMEncrypt(plaintext, plaintext_len, (unsigned char *)"", 0, ciphertext, tag);
    }

    inline int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *plaintext) {
        return GCMDecrypt(ciphertext, ciphertext_len, (unsigned char *)"", 0, tag, plaintext);
    }

private:
	unsigned char *key;
	unsigned char *iv;
	size_t iv_len;

	int GCMEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
	               unsigned char *ciphertext, unsigned char *tag);
	int GCMDecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag,
	               unsigned char *plaintext);
};

} // namespace duckdb
