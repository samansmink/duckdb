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
#include "duckdb/storage/table/column_segment.hpp"

using namespace duckdb;
using namespace std;

long max_buffers_to_free = 100; // TODO this should depend on available mem instead of arbitrary value
vector<data_ptr_t>buffers_to_free;

// Todo deduplicate with definition in sum.cpp
struct sum_state_t {
    double value;
    bool isset;
};
struct secure_sum_state_t {
    data_ptr_t secure_state;
};

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

    buffers_to_free.push_back(*buffer_ptr);

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
//        throw Exception("SGX Free secure buffer ECALL FAILED\n");
//    }
//
//    buffer_ptr = nullptr;
//}

void EnclaveExecutor::PrintAllocedBuffers() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_print_alloced_buffers(global_eid);

    if (ret != SGX_SUCCESS) {
        throw Exception("SGX Free secure buffers ECALL FAILED\n");
    }
}

// Function for debugging to easily print output
void EnclaveExecutor::Decrypt(Vector &vector){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    data_ptr_t encrypted = SGXVector::GetEncryptedData(vector);
    data_ptr_t* decrypted = SGXVector::GetDecryptedData(vector);

    if (*decrypted == nullptr) {

        ret = ecall_decrypt_buffer(global_eid, (void*)(encrypted), (void**) decrypted, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t));
        if (ret != SGX_SUCCESS)
            throw Exception("SGX decrypt ECALL FAILED\n");
    }

    // buffer to move the data outside the enclave
    auto tmp_decryption_buf = (data_ptr_t)malloc(STANDARD_VECTOR_SIZE * GetTypeIdSize(vector.type) + sizeof(nullmask_t));

    ret = ecall_copy_secure_to_unsecure(global_eid, (void**) decrypted, (void*) tmp_decryption_buf, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t));
    if (ret != SGX_SUCCESS)
        throw Exception("SGX decrypt copy ECALL FAILED\n");

    // Note that the variable encrypted will contain the decrypted data after this operation, so the name is confusing
    memcpy(encrypted, tmp_decryption_buf + sizeof(nullmask_t), GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE);

    vector.vector_type = VectorType::FLAT_VECTOR;
    auto nullmask = FlatVector::GetNullmaskPtr(vector);
    memcpy(nullmask, ((data_ptr_t)tmp_decryption_buf), sizeof(nullmask_t));

    free(tmp_decryption_buf);
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
            throw Exception("SGX filter fetch int ECALL FAILED\n");

        break;
    }
    case TypeId::DOUBLE: {
        ret = ecall_filter_fetch_base_data_double(global_eid, (void*)sel.data(), (void**)result_decrypted, (void*)encrypted_data, approved_tuple_count);

        if (ret != SGX_SUCCESS)
            throw Exception("SGX filter fetch double ECALL FAILED\n");

        break;
    }
    default:
        throw InvalidTypeException(type_id, "Invalid type for filter scan");
    }
}

void EnclaveExecutor::AggregateUnaryDoubleUpdateExecutor(Vector &vector, void* state, idx_t count){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    auto encrypted = SGXVector::GetEncryptedData(vector);
    data_ptr_t* decrypted = SGXVector::GetDecryptedData(vector);

    ecall_count++;
    switch (vector.type) {
    case TypeId::DOUBLE: {
		ret = ecall_aggregate_unary_double_update_executor(global_eid, (void *)encrypted, (void **)decrypted,
		                                                   (void *)((secure_sum_state_t *)state)->secure_state, count);
		break;
	}
    case TypeId::INT64: {
        ret = ecall_aggregate_unary_long_update_executor(global_eid, (void *)encrypted, (void **)decrypted,
                                                           (void *)((secure_sum_state_t *)state)->secure_state, count);
        break;
    }
    default:
        throw InvalidTypeException(vector.type, "Invalid type for unary update");
    }

    if (ret != SGX_SUCCESS)
        throw Exception("SGX unary double update executor ECALL FAILED\n");
}

data_ptr_t EnclaveExecutor::CreateSecureAggregateState() {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    data_ptr_t secure_aggregate_state;

    ecall_count++;
    ret = ecall_create_secure_aggregate_state(global_eid, &secure_aggregate_state);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX create scure aggregate ECALL FAILED\n");

    return secure_aggregate_state;
}

void EnclaveExecutor::FreeSecureAggregateState(data_ptr_t secure_aggregate_state) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_free_secure_aggregate_state(global_eid, secure_aggregate_state);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX free secure aggregate state ECALL FAILED\n");
}

void EnclaveExecutor::DecryptAggregateState(data_ptr_t secure_aggregate_state, data_ptr_t unsecure_aggregate_state) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_get_secure_aggregate_state(global_eid, secure_aggregate_state, unsecure_aggregate_state);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX decrypt aggregate state ECALL FAILED\n");
}

bool EnclaveExecutor::GetMinMax(SegmentStatistics &stats, void* min_value, void* max_value){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ecall_count++;
    ret = ecall_get_minmax(global_eid, min_value, max_value, (void*)stats.minimum_secure, (void*)stats.maximum_secure, stats.type_size);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::SetMinMax(SegmentStatistics &stats, void* min_value, void* max_value){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

//    ecall_count++; writing ecalls should not be counted
    ret = ecall_set_minmax(global_eid, min_value, max_value, (void**)&(stats.minimum_secure), (void**)&(stats.maximum_secure), stats.type_size);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

} // namespace duckdb
