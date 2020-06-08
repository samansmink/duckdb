#include "duckdb/common/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace duckdb;
using namespace std;

namespace duckdb {

int aes_ctr_128_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_ctr_128_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

} // namespace duckdb
