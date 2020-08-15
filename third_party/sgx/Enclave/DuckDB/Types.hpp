#pragma once

#define TEST_KEY (const uint8_t*) "0123456789012345678901234567890"
#define TEST_NONCE (uint8_t*)"0123456789012345678901234567890"
#define VECTOR_SIZE 1024
#define NONCE_BYTES 16

typedef uint8_t data_t;
typedef data_t *data_ptr_t;
typedef std::bitset<1024> nullmask_t;
typedef uint64_t idx_t;
typedef uint16_t sel_t;