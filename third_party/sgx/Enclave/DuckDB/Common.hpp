#pragma once

#include "Types.hpp"


extern int buffers_alloced;
void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t buf_size);
void encrypt_buffer(data_ptr_t encrypted, data_ptr_t decrypted, idx_t buf_size);
void assert_buffer_within_enclave(void* ptr, size_t size);
void assert_buffer_outside_enclave(void* ptr, size_t size);
data_ptr_t allocate_buffer(size_t size);
void assert_valid_enclave_buffer(void* ptr, size_t size);
void assert_valid_enclave_buffer(void* ptr);
void free_enclave_buffer(void* ptr);


template<class T> constexpr size_t get_decryption_buffer_size() {
    return STANDARD_VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t);
}

template<class T> constexpr size_t get_encryption_buffer_size() {
    return STANDARD_VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t) + NONCE_BYTES;
}