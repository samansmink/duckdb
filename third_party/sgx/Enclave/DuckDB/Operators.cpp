#include "../Enclave.h"
#include "Enclave_t.h"
#include <bitset>
#include "sgx_tcrypto.h"
#include "Types.hpp"
#include "Common.hpp"

void BinaryDoubleMultiplicationExecutor(double *__restrict ldata,
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
                result_data[i] = lentry * rentry;
            } else {
                result_nullmask[i] = true;
            }
        }
    } else {
        for (idx_t i = 0; i < count; i++) {
            auto lentry = ldata[lsel[i]];
            auto rentry = rdata[rsel[i]];
            result_data[i] = lentry * rentry;
        }
    }
}

void UnaryDoubleSummationUpdateLoop(double *__restrict idata, void *__restrict state, idx_t count, nullmask_t &nullmask) {
    if (nullmask.any()) {
        // potential NULL values and NULL values are ignored
        for (idx_t i = 0; i < count; i++) {
            if (!nullmask[i]) {
                ((sum_state_t*)state)->isset = true;
                ((sum_state_t*)state)->value += idata[i];
            }
        }
    } else {
        // quick path: no NULL values or NULL values are not ignored
        for (idx_t i = 0; i < count; i++) {
            ((sum_state_t*)state)->isset = true;
            ((sum_state_t*)state)->value += idata[i];
        }
    }
}

// Note that all encrypted params should be of format:
// |NONCE|ENCRYPTED NULLMASK|ENCRYPTED DATA|
// All decrypted buffers will be of format:
// |NULLMASK|ENCRYPTED|
void ecall_binary_double_multiplication_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count)
{
    if (*l_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)l_encrypted, (data_ptr_t*)l_decrypted, VECTOR_SIZE * sizeof(double) + sizeof(nullmask_t));
    }

    if (*r_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)r_encrypted, (data_ptr_t*)r_decrypted, VECTOR_SIZE * sizeof(double) + sizeof(nullmask_t));
    }
    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = new data_t[sizeof(double) * VECTOR_SIZE + sizeof(nullmask_t)]; // TODO memleak
        buffers_alloced++;
    }
    // TODO if Decryption buffer exists already -> We should verify if the address is within secure memory to be secure

    // Now create pointers to data for executor
    double* l_decrypted_data = (double*)(((data_ptr_t)*l_decrypted) + sizeof(nullmask_t));
    nullmask_t &l_decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)l_decrypted));
    double* r_decrypted_data = (double*)(((data_ptr_t)*r_decrypted) + sizeof(nullmask_t));
    nullmask_t &r_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)r_decrypted));
    double* result_decrypted_data = (double*)(((data_ptr_t)*result_decrypted) + sizeof(nullmask_t));
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));

    // TODO pointer to result should be copied and checked after copy before calling Executor to prevent security issue?
    BinaryDoubleMultiplicationExecutor(l_decrypted_data, r_decrypted_data, result_decrypted_data, (sel_t*)l_sel, (sel_t*)r_sel, (idx_t)count, l_decrypted_nullmask, r_decrypted_nullmask, result_decrypted_nullmask);
}

// TODO state should be in secure memory
void ecall_aggregate_unary_double_update_executor(void* encrypted, void** decrypted, void* state, int count)
{
    if (*decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, VECTOR_SIZE * sizeof(double) + sizeof(nullmask_t));
    }

    double* decrypted_data = (double*)(((data_ptr_t)*decrypted) + sizeof(nullmask_t));
    nullmask_t &decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)decrypted));

    UnaryDoubleSummationUpdateLoop(decrypted_data, state, count, decrypted_nullmask);
}

void ecall_init_minmax()
{
    print("This ecall will do the minmax initialization\n");
}

void ecall_get_minmax()
{
    print("This ecall will get minmax\n");
}

void ecall_set_minmax()
{
    print("This ecall will get minmax\n");
}