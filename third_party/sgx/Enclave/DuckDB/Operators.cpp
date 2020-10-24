#include "../Enclave.h"
#include "Enclave_t.h"
#include <bitset>
#include "sgx_tcrypto.h"
#include "Types.hpp"
#include "Common.hpp"

template <class T>
void BinaryMultiplicationExecutor(T *__restrict ldata,
                                  T *__restrict rdata,
                                  T *__restrict result_data,
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
//                if (typeid(T) == typeid(double))
//                    print("Multiplying %lf with %lf = %lf\n", lentry, rentry, result_data[i]);
//                else if (typeid(T) == typeid(long))
//                    print("Multiplying %ld with %ld = %ld\n", lentry, rentry, result_data[i]);
            } else {
                result_nullmask[i] = true;
            }
        }
    } else {
        for (idx_t i = 0; i < count; i++) {
            auto lentry = ldata[lsel[i]];
            auto rentry = rdata[rsel[i]];
            result_data[i] = lentry * rentry;
//            if (typeid(T) == typeid(double))
//                print("Multiplying %lf with %lf = %lf\n", lentry, rentry, result_data);
//            else if (typeid(T) == typeid(long))
//                print("Multiplying %ld with %ld = %ld\n", lentry, rentry, result_data);
        }
    }
}

template <class T>
void UnaryDoubleSummationUpdateLoop(T *__restrict idata, void *__restrict state, idx_t count, nullmask_t &nullmask) {
    if (nullmask.any()) {
        // potential NULL values and NULL values are ignored
        for (idx_t i = 0; i < count; i++) {
            if (!nullmask[i]) {
                ((sum_state_t*)state)->isset = true;
                ((sum_state_t*)state)->value += (double)idata[i];
            }
        }
    } else {
        // quick path: no NULL values or NULL values are not ignored
        for (idx_t i = 0; i < count; i++) {
            ((sum_state_t*)state)->isset = true;
            ((sum_state_t*)state)->value += (double)idata[i];
        }
    }
}

template <class T>
void CastNumericToLongExecutor(T *__restrict input_data,
                               int64_t *__restrict result_data,
                               const sel_t *__restrict input_sel,
                               idx_t count,
                               nullmask_t &input_nullmask,
                               nullmask_t &result_nullmask) {

    if (input_nullmask.any()) {
        for (idx_t i = 0; i < count; i++) {
            auto input_index = input_sel[i];
            if (!input_nullmask[input_index]) {
                auto input_entry = input_data[input_index];
                result_data[i] = (int64_t)input_entry;

//                print("Cast %ld to %ld", input_entry, result_data[i]);

            } else {
                result_nullmask[i] = true;
            }
        }
    } else {
        for (idx_t i = 0; i < count; i++) {
            auto input_entry = input_data[input_sel[i]];
            result_data[i] = (int64_t)input_entry;
//            print("Cast %ld to %ld", input_entry, result_data[i]);
        }
    }
}

template <class T>
bool check_zonemap(T* min, T* max, T constant, ExpressionType expr_type) {

    // Zonemap buffers are always 8 currently
    assert_valid_enclave_buffer(min, 8);
    assert_valid_enclave_buffer(max, 8);

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
template <class T>
void binary_multiplication_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count)
{
    assert_buffer_outside_enclave(l_encrypted, get_encryption_buffer_size<T>());
    assert_buffer_outside_enclave(r_encrypted, get_encryption_buffer_size<T>());
    assert_buffer_outside_enclave(l_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(r_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(result_decrypted, sizeof(void*));
    assert_buffer_outside_enclave(l_sel, sizeof(sel_t) * STANDARD_VECTOR_SIZE);
    assert_buffer_outside_enclave(r_sel, sizeof(sel_t) * STANDARD_VECTOR_SIZE);

    if (*l_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)l_encrypted, (data_ptr_t*)l_decrypted, get_decryption_buffer_size<double>());
    } else {
        assert_valid_enclave_buffer(*l_decrypted, get_decryption_buffer_size<T>());
    }

    if (*r_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)r_encrypted, (data_ptr_t*)r_decrypted, get_decryption_buffer_size<T>());
    } else {
        assert_valid_enclave_buffer(*r_decrypted, get_decryption_buffer_size<T>());
    }
    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr || !is_valid_enclave_buffer(*result_decrypted, get_decryption_buffer_size<T>())) {
        *result_decrypted = allocate_buffer(get_decryption_buffer_size<T>()); // TODO memleak
        buffers_alloced++;
    }

    // Initialize nullmask to 0
    memset(*result_decrypted, '\0', sizeof(nullmask_t));

    // Now create pointers to data for executor
    T* l_decrypted_data = (T*)(((data_ptr_t)*l_decrypted) + sizeof(nullmask_t));
    nullmask_t &l_decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)l_decrypted));
    T* r_decrypted_data = (T*)(((data_ptr_t)*r_decrypted) + sizeof(nullmask_t));
    nullmask_t &r_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)r_decrypted));
    T* result_decrypted_data = (T*)(((data_ptr_t)*result_decrypted) + sizeof(nullmask_t));
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));
    BinaryMultiplicationExecutor<T>(l_decrypted_data, r_decrypted_data, result_decrypted_data, (sel_t*)l_sel, (sel_t*)r_sel, (idx_t)count, l_decrypted_nullmask, r_decrypted_nullmask, result_decrypted_nullmask);
}

template <class T>
void aggregate_unary_update_executor(void* encrypted, void** decrypted, void* state, int count)
{
    assert_buffer_outside_enclave(encrypted, get_encryption_buffer_size<T>());
    assert_buffer_outside_enclave(decrypted, sizeof(void*));
    assert_buffer_within_enclave(state, sizeof(sum_state_t));

    if (*decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)decrypted, get_decryption_buffer_size<T>());
    } else {
        assert_valid_enclave_buffer(*decrypted, get_decryption_buffer_size<T>());
    }

    T* decrypted_data = (T*)(((data_ptr_t)*decrypted) + sizeof(nullmask_t));
    nullmask_t &decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)decrypted));

    UnaryDoubleSummationUpdateLoop<T>(decrypted_data, state, count, decrypted_nullmask);
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

template <class T>
void cast_numeric_to_long(void* input_encrypted, void** input_decrypted, void** result_decrypted, void* input_sel, int count) {
    if (*input_decrypted == nullptr) {
        decrypt_buffer((data_ptr_t)input_encrypted, (data_ptr_t*)input_decrypted, get_decryption_buffer_size<T>());
    } else {
        assert_valid_enclave_buffer(*input_decrypted, get_decryption_buffer_size<T>());
    }

    // Only if buffer is suitable do we reuse it
    // TODO validate that this optimization does something
    if (*result_decrypted == nullptr || !is_valid_enclave_buffer(*result_decrypted, get_decryption_buffer_size<T>())) {
        *result_decrypted = allocate_buffer(get_decryption_buffer_size<int64_t>());
        buffers_alloced++;
    }

    memset(*result_decrypted, '\0', sizeof(nullmask_t));

    T* input_decrypted_data = (T*)(((data_ptr_t)*input_decrypted) + sizeof(nullmask_t));
    nullmask_t &input_decrypted_nullmask = *((nullmask_t*)(*(data_ptr_t*)input_decrypted));
    int64_t* result_decrypted_data = (int64_t*)(((data_ptr_t)*result_decrypted) + sizeof(nullmask_t));
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));

    CastNumericToLongExecutor<T>((T*)input_decrypted_data, (int64_t*)result_decrypted_data, (sel_t*)input_sel, (idx_t)count, input_decrypted_nullmask, result_decrypted_nullmask);
}

void ecall_aggregate_unary_double_update_executor(void* encrypted, void** decrypted, void* state, int count) {
    return aggregate_unary_update_executor<double>(encrypted, decrypted, state, count);
}

void ecall_aggregate_unary_long_update_executor(void* encrypted, void** decrypted, void* state, int count) {
    return aggregate_unary_update_executor<int64_t>(encrypted, decrypted, state, count);
}

void ecall_binary_double_multiplication_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count) {
    return binary_multiplication_executor<double>(l_encrypted, l_decrypted, r_encrypted, r_decrypted, result_decrypted, l_sel, r_sel, count);
}
void ecall_binary_long_multiplication_executor(void* l_encrypted, void** l_decrypted, void* r_encrypted, void** r_decrypted, void** result_decrypted, void* l_sel, void* r_sel, int count) {
    return binary_multiplication_executor<int64_t>(l_encrypted, l_decrypted, r_encrypted, r_decrypted, result_decrypted, l_sel, r_sel, count);
}
void ecall_cast_tinyint_to_long(void* input_encrypted, void** input_decrypted, void** result_decrypted, void* input_sel, int count) {
    return cast_numeric_to_long<int8_t>(input_encrypted, input_decrypted, result_decrypted, input_sel, count);
}
void ecall_cast_smallint_to_long(void* input_encrypted, void** input_decrypted, void** result_decrypted, void* input_sel, int count) {
    return cast_numeric_to_long<int16_t>(input_encrypted, input_decrypted, result_decrypted, input_sel, count);
}
void ecall_cast_int_to_long(void* input_encrypted, void** input_decrypted, void** result_decrypted, void* input_sel, int count) {
    return cast_numeric_to_long<int>(input_encrypted, input_decrypted, result_decrypted, input_sel, count);
}

int ecall_check_zonemap_double(double* min_value, double* max_value, double constant, uint8_t expr_type) {
    return check_zonemap<double>((double*) min_value, (double*) max_value, constant, (ExpressionType) expr_type);
}

int ecall_check_zonemap_tinyint(int8_t* min_value, int8_t* max_value, int8_t constant, uint8_t expr_type) {
    return check_zonemap<int8_t>((int8_t*) min_value, (int8_t*) max_value, constant, (ExpressionType) expr_type);
}

int ecall_check_zonemap_smallint(int16_t* min_value, int16_t* max_value, int16_t constant, uint8_t expr_type) {
    return check_zonemap<int16_t>((int16_t*) min_value, (int16_t*) max_value, constant, (ExpressionType) expr_type);
}

int ecall_check_zonemap_int(int* min_value, int* max_value, int constant, uint8_t expr_type) {
    return check_zonemap<int>((int*) min_value, (int*) max_value, constant, (ExpressionType) expr_type);
}

// Test function, unsecure
void ecall_get_minmax(void* min_value, void* max_value, void* min_ptr, void* max_ptr, int type_size) {

    memcpy(min_value, min_ptr, type_size);
    memcpy(max_value, max_ptr, type_size);
}

void ecall_set_minmax_from_secure_buffer(void** min_ptr, void** max_ptr, void* min_value_encrypted, void* max_value_encrypted, uint64_t type_size) {
    // TODO check bounds
    assert_buffer_outside_enclave(min_ptr, sizeof(void*));
    assert_buffer_outside_enclave(max_ptr, sizeof(void*));

    // Currently we just assume the maximum size for all type sizes
    type_size = 8;

    assert_buffer_outside_enclave(min_value_encrypted, type_size + NONCE_BYTES);
    assert_buffer_outside_enclave(max_value_encrypted, type_size + NONCE_BYTES);

    if (!*min_ptr) {
        *min_ptr = allocate_buffer(type_size); // TODO memleak
        buffers_alloced++;
    } else {
        assert_valid_enclave_buffer(*min_ptr, type_size);
    }
    if (!*max_ptr) {
        *max_ptr = allocate_buffer(type_size); // TODO memleak
        buffers_alloced++;
    } else {
        assert_valid_enclave_buffer(*max_ptr, type_size);
    }

    decrypt_buffer((data_ptr_t) min_value_encrypted, (data_ptr_t*) min_ptr, type_size);
    decrypt_buffer((data_ptr_t) max_value_encrypted, (data_ptr_t*) max_ptr, type_size);
}

// Test function unsecure
void ecall_set_minmax(void* min_value, void* max_value, void** min_ptr, void** max_ptr, int type_size) {

    // Currently we just assume the maximum size for all type sizes
    type_size = 8;

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

    assert(*min_ptr != nullptr);
    assert(*max_ptr != nullptr);
}