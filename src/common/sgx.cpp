#include "duckdb/common/sgx.hpp"
#include "Unsecure/App.h"
#include "Unsecure/Enclave_u.h"
#include "sgx_urts.h"
#include <stdio.h>
#include "duckdb/common/printer.hpp"

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

bool EnclaveExecutor::BinaryDoubleAdditionExecutor(Vector &left, Vector &right, Vector &result, idx_t count){
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    // TODO implement for Dict vectors

    auto l_encrypted = SGXVector::GetEncryptedData(left);
    auto r_encrypted = SGXVector::GetEncryptedData(right);
    auto l_decrypted = GetDecryptedData(Vector vector);
    auto r_decrypted = GetDecryptedData(Vector vector);

    auto l_sel = &FlatVector::IncrementalSelectionVector;
    auto r_sel = &FlatVector::IncrementalSelectionVector;

    ret = ecall_binary_double_addition_executor(l_encrypted, l_decrypted, r_encrypted, r_decrypted, result_decrypted, l_sel.data(), r_sel.data(), count);
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
