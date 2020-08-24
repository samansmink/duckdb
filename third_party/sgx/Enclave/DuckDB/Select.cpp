#include "sgx_tcrypto.h"
#include "Types.hpp"
#include "Common.hpp"
#include "../Enclave.h"
#include "Enclave_t.h"

template <class T>
static void templated_assignment(sel_t* sel, data_ptr_t source, data_ptr_t result,
                                 nullmask_t &source_nullmask, nullmask_t &result_nullmask, idx_t approved_tuple_count) {
    if (source_nullmask.any()) {
        for (size_t i = 0; i < approved_tuple_count; i++) {
            if (source_nullmask[sel[i]]) {
                result_nullmask.set(i, true);
            } else {
                ((T *)result)[i] = ((T *)source)[sel[i]];
            }
        }
    } else {
        for (size_t i = 0; i < approved_tuple_count; i++) {
            ((T *)result)[i] = ((T *)source)[sel[i]];
        }
    }
}

template <class T, class OPL, class OPR>
void SelectEncryptedBetween(sel_t* sel, sel_t* new_sel, data_ptr_t result_data, data_ptr_t source, nullmask_t &source_nullmask,
                     const T constantLeft, const T constantRight, idx_t *approved_tuple_count) {
    idx_t result_count = 0;
    if (source_nullmask.any()) {
        for (idx_t i = 0; i < *approved_tuple_count; i++) {
            idx_t src_idx = sel[i];
            if (!(source_nullmask)[src_idx] && OPL::Operation(((T *)source)[src_idx], constantLeft) &&
                OPR::Operation(((T *)source)[src_idx], constantRight)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel[result_count++] = (sel_t)src_idx;
            }
        }
    } else {
        for (idx_t i = 0; i < *approved_tuple_count; i++) {
            idx_t src_idx = sel[i];
            if (OPL::Operation(((T *)source)[src_idx], constantLeft) &&
                OPR::Operation(((T *)source)[src_idx], constantRight)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel[result_count++] = (sel_t)src_idx;
            }
        }
    }
    *approved_tuple_count = result_count;
}

template <class T, class OP>
void SelectEncrypted(sel_t* sel, sel_t* new_sel, data_ptr_t result_data, data_ptr_t source, nullmask_t &source_nullmask, T constant,
                     idx_t *approved_tuple_count) {
    idx_t result_count = 0;
    if (source_nullmask.any()) {
        for (idx_t i = 0; i < *approved_tuple_count; i++) {
            idx_t src_idx = sel[i];
            if (!(source_nullmask)[src_idx] && OP::Operation(((T *)source)[src_idx], constant)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel[result_count++] = (sel_t)src_idx;
            }
        }
    } else {
        for (idx_t i = 0; i < *approved_tuple_count; i++) {
            idx_t src_idx = sel[i];
            if (OP::Operation(((T *)source)[src_idx], constant)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel[result_count++] = (sel_t)src_idx;
            } else {
            }
        }
    }
    *approved_tuple_count = result_count;
}

template <class T>
void filter_fetch_base_data(void* sel, void**result_decrypted, void* encrypted, uint64_t approved_tuple_count) {
    data_t decrypted[VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t)];
    data_ptr_t decrypted_ptr = decrypted;

    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)&decrypted_ptr, VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t));

    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = new data_t[sizeof(T) * VECTOR_SIZE + sizeof(nullmask_t)]; // TODO memleak
        buffers_alloced++;
    }

    data_ptr_t decrypted_data = (decrypted) + sizeof(nullmask_t);
    nullmask_t &decrypted_nullmask = *((nullmask_t*)decrypted);
    data_ptr_t result_decrypted_data = ((data_ptr_t)*result_decrypted) + sizeof(nullmask_t);
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));

    memset(&result_decrypted_nullmask, 0, sizeof(nullmask_t));

    templated_assignment<T>((sel_t*)sel, decrypted_data, result_decrypted_data, decrypted_nullmask, result_decrypted_nullmask, approved_tuple_count);
}

template<class T>
void select(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op, T constant, uint64_t* approved_tuple_count) {
    data_t decrypted[VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t)];
    data_ptr_t decrypted_ptr = decrypted;

    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)&decrypted_ptr, VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t));

    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = new data_t[sizeof(T) * VECTOR_SIZE + sizeof(nullmask_t)]; // TODO memleak
        buffers_alloced++;
    }

    data_ptr_t decrypted_data = (decrypted) + sizeof(nullmask_t);
    nullmask_t &decrypted_nullmask = *((nullmask_t*)decrypted);
    data_ptr_t result_decrypted_data = ((data_ptr_t)*result_decrypted) + sizeof(nullmask_t);
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));
    memset(&result_decrypted_nullmask, 0, sizeof(nullmask_t));

    switch ((ExpressionType)op) {
    case ExpressionType::COMPARE_LESSTHAN: {
        SelectEncrypted<T, LessThan>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant, (idx_t*)approved_tuple_count);
        break;
    }
    // Disabled because of warning for doubles
//    case ExpressionType::COMPARE_EQUAL: {
//        SelectEncrypted<T, Equals>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant, (idx_t*)approved_tuple_count);
//        break;
//    }
    case ExpressionType::COMPARE_GREATERTHAN: {
        SelectEncrypted<T, GreaterThan>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant, (idx_t*)approved_tuple_count);
        break;
    }
    case ExpressionType::COMPARE_LESSTHANOREQUALTO: {
        SelectEncrypted<T, LessThanEquals>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant, (idx_t*)approved_tuple_count);
        break;
    }
    case ExpressionType::COMPARE_GREATERTHANOREQUALTO: {
        SelectEncrypted<T, GreaterThanEquals>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant, (idx_t*)approved_tuple_count);
        break;
    }
    default:
        print("INVALID OPERATION IN ENCLAVE\n");

    }
}

template<class T>
void select_between(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op_left, uint8_t op_right, T constant_left, T constant_right, uint64_t* approved_tuple_count) {
    data_t decrypted[VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t)];
    data_ptr_t decrypted_ptr = decrypted;

    decrypt_buffer((data_ptr_t)encrypted, (data_ptr_t*)&decrypted_ptr, VECTOR_SIZE * sizeof(T) + sizeof(nullmask_t));

    // Allocate secure buffer for result if necessary
    if (*result_decrypted == nullptr) {
        *result_decrypted = new data_t[sizeof(T) * VECTOR_SIZE + sizeof(nullmask_t)]; // TODO memleak
        buffers_alloced++;
    }

    data_ptr_t decrypted_data = (decrypted) + sizeof(nullmask_t);
    nullmask_t &decrypted_nullmask = *((nullmask_t*)decrypted);
    data_ptr_t result_decrypted_data = ((data_ptr_t)*result_decrypted) + sizeof(nullmask_t);
    nullmask_t &result_decrypted_nullmask = *((nullmask_t*) (*(data_ptr_t*)result_decrypted));
    memset(&result_decrypted_nullmask, 0, sizeof(nullmask_t));

    if ((ExpressionType)op_left == ExpressionType::COMPARE_GREATERTHAN) {
        if ((ExpressionType)op_right == ExpressionType::COMPARE_LESSTHAN) {
            SelectEncryptedBetween<T, GreaterThan, LessThan>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant_left, constant_right, (idx_t*)approved_tuple_count);
        } else {
            SelectEncryptedBetween<T, GreaterThan, LessThanEquals>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant_left, constant_right, (idx_t*)approved_tuple_count);
        }
    } else {
        if ((ExpressionType)op_right == ExpressionType::COMPARE_LESSTHAN) {
            SelectEncryptedBetween<T, GreaterThanEquals, LessThan>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant_left, constant_right, (idx_t*)approved_tuple_count);
        } else {
            SelectEncryptedBetween<T, GreaterThanEquals, LessThanEquals>((sel_t*)sel_old, (sel_t*) sel_new, result_decrypted_data, decrypted_data, decrypted_nullmask, constant_left, constant_right, (idx_t*)approved_tuple_count);
        }
    }
}

void ecall_select_integer(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op, int constant, uint64_t* approved_tuple_count)
{
    select<int>(sel_old, sel_new, result_decrypted, encrypted, op, constant, approved_tuple_count);
}

void ecall_select_double(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op, double constant, uint64_t* approved_tuple_count)
{
    select<double>(sel_old, sel_new, result_decrypted, encrypted, op, constant, approved_tuple_count);
}

void ecall_select_integer_between(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op_left, uint8_t op_right, int constant_left, int constant_right, uint64_t* approved_tuple_count)
{
    select_between<int>(sel_old, sel_new, result_decrypted, encrypted, op_left, op_right, constant_left, constant_right, approved_tuple_count);
}

void ecall_select_double_between(void* sel_old, void* sel_new, void**result_decrypted, void* encrypted, uint8_t op_left, uint8_t op_right, double constant_left, double constant_right, uint64_t* approved_tuple_count)
{
    select_between<double>(sel_old, sel_new, result_decrypted, encrypted, op_left, op_right, constant_left, constant_right, approved_tuple_count);
}

void ecall_filter_fetch_base_data_double(void* sel, void**result_decrypted, void* encrypted, uint64_t approved_tuple_count)
{
    filter_fetch_base_data<double>(sel, result_decrypted, encrypted, approved_tuple_count);
}

void ecall_filter_fetch_base_data_int(void* sel, void**result_decrypted, void* encrypted, uint64_t approved_tuple_count)
{
    filter_fetch_base_data<int>(sel, result_decrypted, encrypted, approved_tuple_count);
}