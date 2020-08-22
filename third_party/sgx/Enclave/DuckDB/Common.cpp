#include "../Enclave.h"
#include "Enclave_t.h"

#include "Common.hpp"
#include "Types.hpp"

#include "sgx_tcrypto.h"

unsigned char key[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
unsigned char iv[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};

void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t buf_size) {

    // For some reason the sgx_aes_ctr_decrypt call finds it necessary to modify the NONCE input
    uint8_t nonce_copy[NONCE_BYTES];
    memcpy(nonce_copy, encrypted, NONCE_BYTES);

    if(*decrypted == nullptr){
        *decrypted = new data_t[buf_size];
    }
    // TODO Decryption buffer exists already -> We should verify if the address is within secure memory to be secure (But for now its usefull for debugging)

    sgx_aes_ctr_decrypt(&key,
                        encrypted + NONCE_BYTES,
                        (uint32_t)buf_size,
                        nonce_copy,
                        NONCE_BYTES*8,
                        *decrypted);
}

void ecall_decrypt_buffer(void* encrypted, void** decrypted, uint64_t buf_size) {
    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, (idx_t)buf_size);
}

void ecall_copy_secure_to_unsecure(void** secure, void* unsecure, uint64_t buf_size) {
    if (*secure != nullptr) {
        memcpy((data_ptr_t )unsecure, *(data_ptr_t*)secure, buf_size);
    } else {
        print("copy secure to unsecure called with empty secure buffer");
    }
}