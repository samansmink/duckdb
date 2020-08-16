#include "duckdb/common/sgx.hpp"
#include "Unsecure/App.h"
#include "Unsecure/Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include "duckdb/common/printer.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/crypto.hpp"

using namespace duckdb;
using namespace std;

namespace duckdb {

void EnclaveExecutor::InitializeEnclave(){
    Printer::Print("Initializing SGX Enclave");
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        throw Exception("Something went horribly wrong trying to initialize the SGX Enclave");
    }
}

void EnclaveExecutor::DestroyEnclave(){
    Printer::Print("Deleting SGX Enclave");
    sgx_destroy_enclave(global_eid);
}

bool EnclaveExecutor::Decrypt(Vector &vector){
    printf("Decrypting vector\n");
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    data_ptr_t encrypted = SGXVector::GetEncryptedData(vector);
    data_ptr_t decrypted = (data_ptr_t)malloc(STANDARD_VECTOR_SIZE * GetTypeIdSize(vector.type) + sizeof(nullmask_t));

    ret = ecall_decrypt_buffer(global_eid, (void*)(encrypted), (void**) &decrypted, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t));

//    duckdb::Decrypt(decrypted, encrypted + NONCE_BYTES, GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE + sizeof(nullmask_t), (unsigned char*)TEST_NONCE);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");
    else
        printf("Returned from ECALL\n");

    memcpy(encrypted, ((data_ptr_t)decrypted) + sizeof(nullmask_t), GetTypeIdSize(vector.type) * STANDARD_VECTOR_SIZE);

    vector.vector_type = VectorType::FLAT_VECTOR;
    auto nullmask = FlatVector::GetNullmaskPtr(vector);
    memcpy(nullmask, ((data_ptr_t)decrypted), sizeof(nullmask_t));

    free(decrypted);

    return true;
}

bool EnclaveExecutor::BinaryDoubleAdditionExecutor(Vector &left, Vector &right, Vector &result, idx_t count){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // TODO implement for Dict vectors

    auto l_encrypted = SGXVector::GetEncryptedData(left);
    auto r_encrypted = SGXVector::GetEncryptedData(right);

    data_ptr_t* l_decrypted = SGXVector::GetDecryptedData(left);
    data_ptr_t* r_decrypted = SGXVector::GetDecryptedData(right);
    data_ptr_t* result_decrypted = SGXVector::GetDecryptedData(result);

    ret = ecall_binary_double_addition_executor(global_eid, (void*)l_encrypted, (void**)l_decrypted, (void*)r_encrypted, (void**)r_decrypted, (void**)result_decrypted, (sel_t *)FlatVector::incremental_vector, (sel_t *)FlatVector::incremental_vector, count);
    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::AggregateExecutor(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_aggregate_executor(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::InitMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_init_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::GetMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_get_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}

bool EnclaveExecutor::SetMinMax(){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_set_minmax(global_eid);

    if (ret != SGX_SUCCESS)
        throw Exception("SGX ECALL FAILED\n");

    return true;
}
} // namespace duckdb
