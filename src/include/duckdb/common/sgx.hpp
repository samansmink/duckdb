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

    template <class T>
    static void BinaryMultiplicationExecutor(Vector &left, Vector &right, Vector &result, idx_t count){
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        result.vector_type = VectorType::SGX_VECTOR;

        data_ptr_t l_encrypted;
        data_ptr_t *l_decrypted;
        sel_t* l_sel;
        if (left.vector_type == VectorType::SGX_DICTIONARY_VECTOR) {
            auto l_sel_vec = DictionaryVector::SelVector(left);
            l_sel = l_sel_vec.data();
            auto &child = DictionaryVector::Child(left);
            l_encrypted = SGXVector::GetEncryptedData(child);
            l_decrypted = SGXVector::GetDecryptedData(child);
        } else {
            l_sel = (sel_t*)FlatVector::incremental_vector;
            l_encrypted = SGXVector::GetEncryptedData(left);
            l_decrypted = SGXVector::GetDecryptedData(left);
        }

        data_ptr_t r_encrypted;
        data_ptr_t* r_decrypted;
        sel_t* r_sel;
        if (right.vector_type == VectorType::SGX_DICTIONARY_VECTOR) {
            auto r_sel_vec = DictionaryVector::SelVector(right);
            r_sel = r_sel_vec.data();
            auto &child = DictionaryVector::Child(right);
            r_encrypted = SGXVector::GetEncryptedData(child);
            r_decrypted = SGXVector::GetDecryptedData(child);
        } else {
            r_sel = (sel_t*)FlatVector::incremental_vector;
            r_encrypted = SGXVector::GetEncryptedData(right);
            r_decrypted = SGXVector::GetDecryptedData(right);
        }

        data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

        ecall_count++;


        if (typeid(T) == typeid(double))
            ret = ecall_binary_double_multiplication_executor(global_eid, (void*)l_encrypted, (void**)l_decrypted, (void*)r_encrypted, (void**)r_decrypted, (void**)result_decrypted, l_sel, r_sel, count);
        else if (typeid(T) == typeid(long)) {
            ret = ecall_binary_long_multiplication_executor(global_eid, (void*)l_encrypted, (void**)l_decrypted, (void*)r_encrypted, (void**)r_decrypted, (void**)result_decrypted, l_sel, r_sel, count);
        } else {
            throw Exception("Unimplemented type in SGX mult operator\n");
        }



        if (ret != SGX_SUCCESS)
            throw Exception("SGX binary double multiplication ECALL FAILED\n");
    }

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
        } else if (typeid(T) == typeid(int8_t)) {
            ecall_select_tinyinteger(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type, constant, (uint64_t*)&approved_tuple_count);
        } else if (typeid(T) == typeid(int16_t)) {
            ecall_select_smallinteger(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type, constant, (uint64_t*)&approved_tuple_count);
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
        } else if (typeid(T) == typeid(int8_t)) {
            ecall_select_tinyinteger_between(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type_left, (uint8_t) expr_type_right, constant_left, constant_right, (uint64_t*)&approved_tuple_count);
        } else if (typeid(T) == typeid(int16_t)) {
            ecall_select_smallinteger_between(global_eid, (void*)sel.data(), (void*)new_sel.data(), (void**)result_decrypted, (void*)encrypted_data, (uint8_t) expr_type_left, (uint8_t) expr_type_right, constant_left, constant_right, (uint64_t*)&approved_tuple_count);
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

        if (stats.minimum_secure == nullptr || stats.maximum_secure == nullptr)
            throw new Exception("min/max value is nullptr");

        int retval;
        ecall_count++;
        if (typeid(T) == typeid(int)) {
            ecall_check_zonemap_int(global_eid, &retval, (int*)stats.minimum_secure, (int*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else if (typeid(T) == typeid(int8_t)) {
            ecall_check_zonemap_tinyint(global_eid, &retval, (int8_t*)stats.minimum_secure, (int8_t*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else if (typeid(T) == typeid(int16_t)) {
            ecall_check_zonemap_smallint(global_eid, &retval, (int16_t*)stats.minimum_secure, (int16_t*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else if (typeid(T) == typeid(double)) {
            ecall_check_zonemap_double(global_eid, &retval, (double*)stats.minimum_secure, (double*)stats.maximum_secure, constant, (uint8_t) expr_type);
        } else {
            throw Exception("Unimplemented type in SGX select operator\n");
        }
        return (bool)retval;
    }

    template<class T>
    static void CastToLong(Vector &input, Vector &result, idx_t count) {

        data_ptr_t input_encrypted;
        data_ptr_t *input_decrypted;
        sel_t* input_sel;
        if (input.vector_type == VectorType::SGX_DICTIONARY_VECTOR) {
            auto input_sel_vec = DictionaryVector::SelVector(input);
            input_sel = input_sel_vec.data();
            auto &child = DictionaryVector::Child(input);
            input_encrypted = SGXVector::GetEncryptedData(child);
            input_decrypted = SGXVector::GetDecryptedData(child);
        } else {
            input_sel = (sel_t*)FlatVector::incremental_vector;
            input_encrypted = SGXVector::GetEncryptedData(input);
            input_decrypted = SGXVector::GetDecryptedData(input);
        }

        result.vector_type = VectorType::SGX_VECTOR;
        data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

        if (typeid(T) == typeid(int8_t)) {
            ecall_cast_tinyint_to_long(global_eid, (void*)input_encrypted, (void**)input_decrypted, (void**)result_decrypted, input_sel, count);
        } else if (typeid(T) == typeid(int16_t)) {
            ecall_cast_smallint_to_long(global_eid, (void*)input_encrypted, (void**)input_decrypted, (void**)result_decrypted, input_sel, count);
        } else if (typeid(T) == typeid(int)) {
            ecall_cast_int_to_long(global_eid, (void*)input_encrypted, (void**)input_decrypted, (void**)result_decrypted, input_sel, count);
        } else {
            throw Exception("Unimplemented type in SGX cast operator\n");
        }
    }

    static bool GetMinMax(SegmentStatistics &stats, void* min_value, void* max_value);
    static bool SetMinMax(SegmentStatistics &stats, void* min_value, void* max_value);
    static void SetSecureBuffer(data_ptr_t* secure_buffer, data_ptr_t unsecure_encrypted_buffer, size_t buf_size);
    static void SetMinMaxFromSecureBuffer(SegmentStatistics &stats, void* min_value_encrypted, void* max_value_encrypted);
    static void GetSecureBuffer(data_ptr_t unsecure_encrypted_buffer, data_ptr_t* secure_buffer, size_t buf_size);
};
}