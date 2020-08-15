#include "../Enclave.h"
#include "Enclave_t.h"
#include <bitset>
#include "sgx_tcrypto.h"
#include "Types.hpp"

//typedef struct {
//    unsigned char nonce[NONCE_BYTES];
//    unsigned char nullmask[sizeof(nullmask_t)];
//} encrypted_vector_header_t;

void BinaryDoubleAdditionExecutor(double *__restrict ldata,
    double *__restrict rdata,
    double *__restrict result_data,
    const sel_t *__restrict lsel,
    const sel_t *__restrict rsel,
    idx_t count,
    nullmask_t &lnullmask,
    nullmask_t &rnullmask,
    nullmask_t &result_nullmask) {

    if (lnullmask.any() || rnullmask.any()) {
        for (idx_t i = 0; i < count; i++) {
            auto lindex = lsel[i];
            auto rindex = rsel[i];
            if (!lnullmask[lindex] && !rnullmask[rindex]) {
                auto lentry = ldata[lindex];
                auto rentry = rdata[rindex];
                result_data[i] = lentry + rentry;
            } else {
                result_nullmask[i] = true;
            }
        }
    } else {
        for (idx_t i = 0; i < count; i++) {
            auto lentry = ldata[lsel[i]];
            auto rentry = rdata[rsel[i]];
            result_data[i] = lentry + rentry;
        }
    }
}

void decrypt_buffer(data_ptr_t encrypted, data_ptr_t* decrypted, idx_t length, size_t data_size) {
    if(*decrypted == nullptr){
        *decrypted = new data_t[data_size * length];

        sgx_aes_ctr_decrypt((const sgx_aes_gcm_128bit_key_t *)TEST_KEY,
            encrypted,
            (uint32_t)length * (uint32_t)data_size,
            TEST_NONCE,
            NONCE_BYTES,
            *decrypted);
        return;
    } else {
        // TODO Decryption buffer exists already -> We should verify if the address is within secure memory to be secure

        return;
    }
}

void ecall_binary_double_addition_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count)
{
    // Decrypt encrypted vectors
    decrypt_buffer((data_ptr_t)l_encrypted, (data_ptr_t*)l_decrypted, VECTOR_SIZE, sizeof(double));
    decrypt_buffer((data_ptr_t)r_encrypted, (data_ptr_t*)r_decrypted, VECTOR_SIZE, sizeof(double));

    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = new data_t[sizeof(double) * VECTOR_SIZE];
    }
    // TODO if Decryption buffer exists already -> We should verify if the address is within secure memory to be secure

    // Now create pointers to data for executor
    double* l_decrypted_data = (double*)((data_ptr_t)*l_decrypted) + sizeof(nullmask_t);
    nullmask_t &l_decrypted_nullmask = *((nullmask_t*) l_decrypted);
    double* r_decrypted_data = (double*)((data_ptr_t)*r_decrypted) + sizeof(nullmask_t);
    nullmask_t &r_decrypted_nullmask = *((nullmask_t*) r_decrypted);
    double* result_decrypted_data = (double*)((data_ptr_t)*result_decrypted) + sizeof(nullmask_t);
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) result_decrypted);

    // TODO pointer to result should be copied and checked after copy before calling Executor to prevent security issue?
    BinaryDoubleAdditionExecutor(l_decrypted_data, r_decrypted_data, result_decrypted_data, (sel_t*)l_sel, (sel_t*)r_sel, (idx_t)count, l_decrypted_nullmask, r_decrypted_nullmask, result_decrypted_nullmask);
}

void ecall_aggregate_executor()
{
    printf("This ecall will do the aggregate execution\n");
}

void ecall_init_minmax()
{
    printf("This ecall will do the minmax initialization\n");
}

void ecall_get_minmax()
{
    printf("This ecall will get minmax\n");
}

void ecall_set_minmax()
{
    printf("This ecall will get minmax\n");
}