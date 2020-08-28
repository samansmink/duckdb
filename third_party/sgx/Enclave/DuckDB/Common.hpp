#pragma once

#include "Types.hpp"


extern int buffers_alloced;
void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t buf_size);
void encrypt_buffer(data_ptr_t encrypted, data_ptr_t decrypted, idx_t buf_size);