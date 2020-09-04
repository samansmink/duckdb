#include "../Enclave.h"
#include "Enclave_t.h"

#include "Common.hpp"
#include "Types.hpp"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include <unordered_map>

unsigned char key[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
unsigned char iv[16] = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};

int buffers_alloced = 0;

std::unordered_map<data_ptr_t, size_t> allocated_buffers;

// Todo decrypted can be data_ptr_t
void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t buf_size) {

    // For some reason the sgx_aes_ctr_decrypt call finds it necessary to modify the NONCE input
    uint8_t nonce_copy[NONCE_BYTES];
    memcpy(nonce_copy, encrypted, NONCE_BYTES);

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

data_ptr_t allocate_buffer(size_t size) {
    data_ptr_t ptr = (data_ptr_t) new data_t[size];
    allocated_buffers[ptr] = size;
    return ptr;
}

// Note, does not check if ptr is actually valid buffer!
void free_enclave_buffer(void* ptr) {
    delete (data_ptr_t)ptr;
    allocated_buffers.erase((data_ptr_t) ptr);
}

void assert_buffer_within_enclave(void* ptr, size_t size) {
    assert(sgx_is_within_enclave(ptr, size));
}
void assert_buffer_outside_enclave(void* ptr, size_t size) {
    assert(sgx_is_outside_enclave(ptr, size));
}

// Since the ptrs inserted into allocated buffers can only come from the allocator inside the enclave this also verifies that they lie within the enclave
void assert_valid_enclave_buffer(void* ptr, size_t size) {
    auto lookup = allocated_buffers.find((data_ptr_t)ptr);
    assert(lookup != allocated_buffers.end());
    assert(lookup->second == size);
}

void assert_valid_enclave_buffer(void* ptr) {
    auto lookup = allocated_buffers.find((data_ptr_t)ptr);
    assert(lookup != allocated_buffers.end());
}

// Test function, unsecure
void ecall_decrypt_buffer(void* encrypted, void** decrypted, uint64_t buf_size) {
    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, (idx_t)buf_size);
}

// Test function, unsecure
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

// Test function, unsecure
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
    assert_buffer_outside_enclave(secure_buffer_ptr, sizeof(void*));

    assert_valid_enclave_buffer(*secure_buffer_ptr);
    free_enclave_buffer(*secure_buffer_ptr);
    buffers_alloced--;
}

void ecall_free_secure_buffers(void** buffers_to_free, uint64_t count) {
    assert_buffer_outside_enclave(buffers_to_free, sizeof(void*) * count);

    for (unsigned  int i = 0; i < count; ++i) {
        assert_valid_enclave_buffer(buffers_to_free[i]);
        auto secure_buffer_ptr = buffers_to_free[i]; // TODO Bounds check ptr
        free_enclave_buffer(secure_buffer_ptr);
        buffers_alloced--;
    }
}