#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/storage/data_table.hpp"
#include "duckdb/common/operator/comparison_operators.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/storage/encrypted_segment.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/transaction/update_info.hpp"

using namespace duckdb;
using namespace std;

EncryptedSegment::~EncryptedSegment() {
    if (block_id >= MAXIMUM_BLOCK) {
        // if the uncompressed segment had an in-memory segment, destroy it when the uncompressed segment is destroyed
        manager.DestroyBuffer(block_id);
    }
}