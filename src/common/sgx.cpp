#include "duckdb/common/sgx.hpp"
#include "Unsecure/App.h"
#include "Unsecure/Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include "duckdb/common/printer.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/crypto.hpp"
#include "duckdb/common/enums/expression_type.hpp"
#include "duckdb/common/counter.hpp"

using namespace duckdb;
using namespace std;

long max_buffers_to_free = 100; // TODO this should depend on available mem instead of arbitrary value
vector<void*>buffers_to_free;

namespace duckdb {

void EnclaveExecutor::InitializeEnclave(){
    Printer::Print("Initializing SGX Enclave");
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        throw Exception("Something went horribly wrong trying to initialize the SGX Enclave");
    }
}

void EnclaveExecutor::DestroyEnclave(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    Printer::Print("Deleting SGX Enclave");

    PrintAllocedBuffers();

    sgx_destroy_enclave(global_eid);
}

void EnclaveExecutor::FreeSecureBuffer(data_ptr_t* buffer_ptr) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    buffers_to_free.push_back((void*)*buffer_ptr);

    if (buffers_to_free.size() >= max_buffers_to_free) {
        ecall_count++;
        ret = ecall_free_secure_buffers(global_eid, (void**)&buffers_to_free[0], buffers_to_free.size());
        buffers_to_free.clear();

        if (ret != SGX_SUCCESS) {
            throw Exception("SGX ECALL FAILED\n");
        }
    }
}

// Ecall per free approach
//void EnclaveExecutor::FreeSecureBuffer(data_ptr_t* buffer_ptr) {
//    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//
//    ecall_count++;
//    ret = ecall_free_secure_buffer(global_eid, (void**)buffer_ptr);
//
//    if (ret != SGX_SUCCESS) {
//        throw Exception("SGX ECALL FAILED\n");
//    }
//}

void EnclaveExecutor::PrintAllocedBuffers() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_print_alloced_buffers(global_eid);

    if (ret != SGX_SUCCESS) {
        throw Exception("SGX ECALL FAILED\n");
    }
}

// Function for debugging to easily print output
bool EnclaveExecutor::Decrypt(Vector &vector){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    data_ptr_t encrypted = SGXVector::GetEncryptedData(vector);
    data_ptr_t* decrypted = SGXVector::GetDecryptedData(vector);

    if (*decrypted == nullptr) {

        ret = ecall_decrypt_buffer(global_eid, (void*)(encrypted), (void**) decrypted, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t));
        if (ret != SGX_SUCCESS)
            throw Exception("SGX ECALL FAILED\n");
    }

    // buffer to move the data outside the enclave
    auto tmp_decryption_buf = (data_ptr_t)malloc(STANDARD_VECTOR_SIZE * GetTypeIdSize(vector.type) + sizeof(nullmask_t));

    ret = ecall_copy_secure_to_unsecure(global_eid, (void**) decrypted, (void*) tmp_decryption_buf, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t));
    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    // Note that the variable encrypted will contain the decrypted data after this operation, so the name is confusing
    memcpy(encrypted, tmp_decryption_buf + sizeof(nullmask_t), GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE);

    vector.vector_type = VectorType::FLAT_VECTOR;
    auto nullmask = FlatVector::GetNullmaskPtr(vector);
    memcpy(nullmask, ((data_ptr_t)tmp_decryption_buf), sizeof(nullmask_t));

    free(tmp_decryption_buf);

    return true;
}

// TODO Does not work when vectors left and right point to same data, ecall seems to compromise encrypted data?
bool EnclaveExecutor::BinaryDoubleMultiplicationExecutor(Vector &left, Vector &right, Vector &result, idx_t count){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    result.vector_type = VectorType::SGX_VECTOR;

    // TODO implement for Dict vectors

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
    ret = ecall_binary_double_multiplication_executor(global_eid, (void*)l_encrypted, (void**)l_decrypted, (void*)r_encrypted, (void**)r_decrypted, (void**)result_decrypted, l_sel, r_sel, count);
    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

void EnclaveExecutor::FilterFetchBaseData(data_ptr_t encrypted_data, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count, TypeId type_id) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    result.vector_type = VectorType::SGX_VECTOR;

    data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

    ecall_count++;
    switch (type_id) {
    case TypeId::INT32: {
        ret = ecall_filter_fetch_base_data_int(global_eid, (void*)sel.data(), (void**)result_decrypted, (void*)encrypted_data, approved_tuple_count);

        if (ret != SGX_SUCCESS)
            throw Exception("SGX ECALL FAILED\n");

        break;
    }
    case TypeId::DOUBLE: {
        ret = ecall_filter_fetch_base_data_double(global_eid, (void*)sel.data(), (void**)result_decrypted, (void*)encrypted_data, approved_tuple_count);

        if (ret != SGX_SUCCESS)
            throw Exception("SGX ECALL FAILED\n");

        break;
    }
    default:
        throw InvalidTypeException(type_id, "Invalid type for filter scan");
    }
}

bool EnclaveExecutor::AggregateUnaryDoubleUpdateExecutor(Vector &vector, void* state, idx_t count){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    auto encrypted = SGXVector::GetEncryptedData(vector);
    data_ptr_t* decrypted = SGXVector::GetDecryptedData(vector);

    ecall_count++;
    ret = ecall_aggregate_unary_double_update_executor(global_eid, (void*)encrypted, (void**)decrypted, state, count);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::InitMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_init_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::GetMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_get_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::SetMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_set_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}
} // namespace duckdb
