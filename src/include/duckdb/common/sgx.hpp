//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/file_buffer.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/enums/expression_type.hpp"
#include "Unsecure/App.h"
#include "Unsecure/Enclave_u.h"
#include "duckdb/common/counter.hpp"
#include "duckdb/storage/table/column_segment.hpp"

extern "C" {
#include "chacha.h"
};

namespace duckdb {

struct EnclaveExecutor {

    static void InitializeEnclave();
    static void DestroyEnclave();
    static void Decrypt(Vector &vector);
    static void FreeSecureBuffer(data_ptr_t* buffer_ptr);
    static void PrintAllocedBuffers();

    // Binary Executors
    static void BinaryDoubleMultiplicationExecutor(Vector &left, Vector &right, Vector &result, idx_t count);

    // Aggregate Executors
    static void AggregateUnaryDoubleUpdateExecutor(Vector &vector, void* state, idx_t count);
    static data_ptr_t CreateSecureAggregateState();
    static void FreeSecureAggregateState(data_ptr_t secure_aggregate_state);
    static void DecryptAggregateState(data_ptr_t secure_aggregate_state, data_ptr_t unsecure_aggregate_state);

    // Select operators
    template<class T>
    static void Select(data_ptr_t encrypted_data, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count, ExpressionType expr_type, T constant) {
        SelectionVector new_sel(approved_tuple_count);

        result.vector_type = VectorType::SGX_VECTOR;
        data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

        ecall_count++;
        if (typeid(T) == typeid(int)) {
            ecall_select_integer(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type, constant, (uint64_t*)&approved_tuple_count);
        } else if (typeid(T) == typeid(double)) {
            ecall_select_double(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type, constant, (uint64_t*)&approved_tuple_count);
        } else {
            throw Exception("Unimplemented type in SGX select operator\n");
        }

        sel.Initialize(new_sel);
    }

    template<class T>
    static void SelectBetween(data_ptr_t encrypted_data, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count, ExpressionType expr_type_left, ExpressionType expr_type_right, T constant_left, T constant_right) {
        SelectionVector new_sel(approved_tuple_count);

        result.vector_type = VectorType::SGX_VECTOR;
        data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

        ecall_count++;
        if (typeid(T) == typeid(int)) {
            ecall_select_integer_between(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type_left, (uint8_t) expr_type_right, constant_left, constant_right, (uint64_t*)&approved_tuple_count);
        } else if (typeid(T) == typeid(double)) {
            ecall_select_double_between(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type_left, (uint8_t) expr_type_right, constant_left, constant_right, (uint64_t*)&approved_tuple_count);
        } else {
            throw Exception("Unimplemented type in SGX select operator\n");
        }

        sel.Initialize(new_sel);
    }

    static void FilterFetchBaseData(data_ptr_t encrypted_data, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count, TypeId type_id);

    // Zonemap handling
    template<class T>
    static bool CheckZoneMap(SegmentStatistics &stats, T constant, ExpressionType expr_type) {
        int retval;
        ecall_count++;
        if (typeid(T) == typeid(int)) {
            ecall_check_zonemap_int(global_eid, &retval, (int*)stats.minimum_secure, (int*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else if (typeid(T) == typeid(double)) {
            ecall_check_zonemap_double(global_eid, &retval, (double*)stats.minimum_secure, (double*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else {
            throw Exception("Unimplemented type in SGX select operator\n");
        }
        return (bool)retval;
    }
    static bool GetMinMax(SegmentStatistics &stats, void* min_value, void* max_value);
    static bool SetMinMax(SegmentStatistics &stats, void* min_value, void* max_value);
};
}