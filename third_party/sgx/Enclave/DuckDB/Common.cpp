#include "../Enclave.h"
#include "Enclave_t.h"

#include "Common.hpp"
#include "Types.hpp"

#include "sgx_tcrypto.h"

unsigned char key[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
unsigned char iv[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};

int buffers_alloced = 0;

void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t buf_size) {

    // For some reason the sgx_aes_ctr_decrypt call finds it necessary to modify the NONCE input
    uint8_t nonce_copy[NONCE_BYTES];
    memcpy(nonce_copy, encrypted, NONCE_BYTES);

    if(*decrypted == nullptr){
        *decrypted = new data_t[buf_size];
        buffers_alloced++;
    }
    // TODO Decryption buffer exists already -> We should verify if the address is within secure memory to be secure (But for now its usefull for debugging)

    sgx_aes_ctr_decrypt(&key,
                        encrypted + NONCE_BYTES,
                        (uint32_t)buf_size,
                        nonce_copy,
                        NONCE_BYTES*8,
                        *decrypted);
}

void encrypt_buffer(data_ptr_t encrypted, data_ptr_t decrypted, idx_t buf_size) {

    // For some reason the sgx_aes_ctr_decrypt call finds it necessary to modify the NONCE input
    uint8_t nonce_copy[NONCE_BYTES];
    memcpy(nonce_copy, iv, NONCE_BYTES);

    sgx_aes_ctr_encrypt(&key,
                        decrypted,
                        (uint32_t)buf_size,
                        nonce_copy,
                        NONCE_BYTES*8,
                        encrypted);
}

void ecall_decrypt_buffer(void* encrypted, void** decrypted, uint64_t buf_size) {
    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, (idx_t)buf_size);
}

void ecall_encrypt_buffer(void* encrypted, void* decrypted, uint64_t buf_size) {
    encrypt_buffer((data_ptr_t)encrypted, (data_ptr_t)decrypted, (idx_t)buf_size);
}

void ecall_benchmark_decryption(void* encrypted, uint64_t buf_size, uint64_t num_loops) {

    data_ptr_t decryption_buffer = nullptr;

    for (unsigned int i = 0; i < num_loops; ++i) {
        decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)&decryption_buffer, (idx_t)buf_size);
    }
}

void ecall_benchmark_decryption_nop(void* encrypted, uint64_t buf_size, uint64_t num_loops) {
    (void)encrypted;
    (void)buf_size;
    (void)num_loops;
}


void ecall_copy_secure_to_unsecure(void** secure, void* unsecure, uint64_t buf_size) {
    if (*secure != nullptr) {
        memcpy((data_ptr_t )unsecure, *(data_ptr_t*)secure, buf_size);
    } else {
        print("copy secure to unsecure called with empty secure buffer");
    }
}

void ecall_print_alloced_buffers() {
    print("Currently %d vector buffers still need to be freed\n", buffers_alloced);
}

void ecall_free_secure_buffer(void ** secure_buffer_ptr) {

    delete *(data_ptr_t*)secure_buffer_ptr;
    buffers_alloced--;
}

// triple pointer for maximum fun
void ecall_free_secure_buffers(void** buffers_to_free, uint64_t count) {

    for (unsigned  int i = 0; i < count; ++i) {
        auto secure_buffer_ptr = buffers_to_free[i]; // TODO Bounds check ptr
        delete (data_ptr_t)secure_buffer_ptr;
        buffers_alloced--;
    }
}