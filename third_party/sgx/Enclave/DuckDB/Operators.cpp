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

template <class T>
bool check_zonemap(T* min, T* max, T constant, ExpressionType expr_type) {
    assert_valid_enclave_buffer(min, sizeof(T));
    assert_valid_enclave_buffer(max, sizeof(T));

    switch (expr_type) {
    case ExpressionType::COMPARE_EQUAL:
        return constant >= *min && constant <= *max;
    case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
        return constant <= *max;
    case ExpressionType::COMPARE_GREATERTHAN:
        return constant < *max;
    case ExpressionType::COMPARE_LESSTHANOREQUALTO:
        return constant >= *min;
    case ExpressionType::COMPARE_LESSTHAN:
        return constant > *min;
    default:
        print("Enclave Zonemap check found incorrect expression type.\n");
        return 0;
    }
}


// Note that all encrypted params should be of format:
// |NONCE|ENCRYPTED NULLMASK|ENCRYPTED DATA|
// All decrypted buffers will be of format:
// |NULLMASK|ENCRYPTED|
void ecall_binary_double_multiplication_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count)
{
    assert_buffer_outside_enclave(l_encrypted, get_encryption_buffer_size<double>());
    assert_buffer_outside_enclave(r_encrypted, get_encryption_buffer_size<double>());
    assert_buffer_outside_enclave(l_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(r_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(result_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(l_sel, sizeof(sel_t) * STANDARD_VECTOR_SIZE);
    assert_buffer_outside_enclave(r_sel, sizeof(sel_t) * STANDARD_VECTOR_SIZE);

    if (*l_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)l_encrypted, (data_ptr_t*)l_decrypted, get_decryption_buffer_size<double>());
    } else {
        assert_valid_enclave_buffer(*l_decrypted, get_decryption_buffer_size<double>());
    }

    if (*r_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)r_encrypted, (data_ptr_t*)r_decrypted, get_decryption_buffer_size<double>());
    } else {
        assert_valid_enclave_buffer(*r_decrypted, get_decryption_buffer_size<double>());
    }
    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = allocate_buffer(get_decryption_buffer_size<double>()); // TODO memleak

        // Initialize nullmask to 0
        memset(*result_decrypted, '\0', sizeof(nullmask_t));
        buffers_alloced++;
    } else {
        assert_valid_enclave_buffer(*result_decrypted, get_decryption_buffer_size<double>());
        memset(*result_decrypted, '\0', sizeof(nullmask_t));
    }

    // Now create pointers to data for executor
    double* l_decrypted_data = (double*)(((data_ptr_t)*l_decrypted) + sizeof(nullmask_t));
    nullmask_t &l_decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)l_decrypted));
    double* r_decrypted_data = (double*)(((data_ptr_t)*r_decrypted) + sizeof(nullmask_t));
    nullmask_t &r_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)r_decrypted));
    double* result_decrypted_data = (double*)(((data_ptr_t)*result_decrypted) + sizeof(nullmask_t));
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));
    BinaryDoubleMultiplicationExecutor(l_decrypted_data, r_decrypted_data, result_decrypted_data, (sel_t*)l_sel, (sel_t*)r_sel, (idx_t)count, l_decrypted_nullmask, r_decrypted_nullmask, result_decrypted_nullmask);
}

void ecall_aggregate_unary_double_update_executor(void* encrypted, void** decrypted, void* state, int count)
{
    assert_buffer_outside_enclave(encrypted, get_encryption_buffer_size<double>());
    assert_buffer_outside_enclave(decrypted, sizeof(void*));
    assert_buffer_within_enclave(state, sizeof(sum_state_t));

    if (*decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, get_decryption_buffer_size<double>());
    } else {
        assert_valid_enclave_buffer(*decrypted, get_decryption_buffer_size<double>());
    }

    double* decrypted_data = (double*)(((data_ptr_t)*decrypted) + sizeof(nullmask_t));
    nullmask_t &decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)decrypted));

    UnaryDoubleSummationUpdateLoop(decrypted_data, state, count, decrypted_nullmask);
}

void ecall_create_secure_aggregate_state(void* secure_aggregate_state) {
    // Validate secure_sum_state_t struct is outside enclave
    assert_buffer_outside_enclave(secure_aggregate_state, sizeof(secure_sum_state_t));
    ((secure_sum_state_t*)secure_aggregate_state)->secure_state = (sum_state_t*)allocate_buffer(sizeof(sum_state_t));
}


void ecall_free_secure_aggregate_state(void* secure_aggregate_state) {

    assert_buffer_outside_enclave(secure_aggregate_state, sizeof(secure_sum_state_t));
    auto secure_buffer = ((secure_sum_state_t*)secure_aggregate_state)->secure_state;
    assert_valid_enclave_buffer(secure_buffer,sizeof(sum_state_t));
    free_enclave_buffer(secure_buffer);
}

// Test function, unsecure
void ecall_get_secure_aggregate_state(void* secure_aggregate_state, void* unsecure_aggregate_state) {

    auto secure = (secure_sum_state_t*) secure_aggregate_state;
    auto unsecure = (sum_state_t*) unsecure_aggregate_state;

    // copy state from secure memory to unsecure memory
    *unsecure = *(secure->secure_state);
}

int ecall_check_zonemap_double(double* min_value, double* max_value, double constant, uint8_t expr_type) {
    return check_zonemap<double>((double*) min_value, (double*) max_value, constant, (ExpressionType) expr_type);
}

int ecall_check_zonemap_int(int* min_value, int* max_value, int constant, uint8_t expr_type) {
    return check_zonemap<int>((int*) min_value, (int*) max_value, constant, (ExpressionType) expr_type);
}

// Test function, unsecure
void ecall_get_minmax(void* min_value, void* max_value, void* min_ptr, void* max_ptr, int type_size) {

    if (min_ptr) memcpy(min_value, min_ptr, type_size);
    if (max_ptr) memcpy(max_value, max_ptr, type_size);
}

// Test function unsecure
void ecall_set_minmax(void* min_value, void* max_value, void** min_ptr, void** max_ptr, int type_size) {
    if (!*min_ptr) {
        *min_ptr = allocate_buffer(type_size); // TODO memleak
        buffers_alloced++;
    }
    if (!*max_ptr) {
        *max_ptr = allocate_buffer(type_size); // TODO memleak
        buffers_alloced++;
    }

    // Copy min_max into value
    memcpy(*min_ptr, min_value, type_size);
    memcpy(*max_ptr, max_value, type_size);
}