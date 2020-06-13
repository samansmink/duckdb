//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/storage/numeric_encrypted_segment.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/storage/encrypted_segment.hpp"
#include "duckdb/common/crypto.hpp"

namespace duckdb {

typedef struct {
    unsigned char nullmask_nonce[NONCE_BYTES];
    unsigned char nullmask[sizeof(nullmask_t)];
    unsigned char data_nonce[NONCE_BYTES];
} encrypted_vector_header_t;

class NumericEncryptedSegment : public EncryptedSegment {
public:
	NumericEncryptedSegment(BufferManager &manager, TypeId type, idx_t row_start, block_id_t block_id = INVALID_BLOCK);

	//! The size of this type
	idx_t type_size;

public:
	//! Fetch a single value and append it to the vector
	void FetchRow(ColumnFetchState &state, Transaction &transaction, row_t row_id, Vector &result,
	              idx_t result_idx) override;

	//! Append a part of a vector to the encrypted segment with the given append state, updating the provided stats
	//! in the process. Returns the amount of tuples appended. If this is less than `count`, the encrypted segment is
	//! full.
	idx_t Append(SegmentStatistics &stats, Vector &data, idx_t offset, idx_t count) override;

	//! Rollback a previous update
	void RollbackUpdate(UpdateInfo *info) override;

protected:
	void Update(ColumnData &data, SegmentStatistics &stats, Transaction &transaction, Vector &update, row_t *ids,
	            idx_t count, idx_t vector_index, idx_t vector_offset, UpdateInfo *node) override;
	void Select(ColumnScanState &state, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count,
	            vector<TableFilter> &tableFilter) override;
	void FetchBaseData(ColumnScanState &state, idx_t vector_index, Vector &result) override;
	void FilterFetchBaseData(ColumnScanState &state, Vector &result, SelectionVector &sel,
	                         idx_t &approved_tuple_count) override;
	void FetchUpdateData(ColumnScanState &state, Transaction &transaction, UpdateInfo *versions,
	                     Vector &result) override;

public:
	typedef void (*append_function_t)(SegmentStatistics &stats, data_ptr_t target, idx_t target_offset, Vector &source,
	                                  idx_t offset, idx_t count);

private:
	append_function_t append_function;

	unique_ptr<unsigned char[]> decryption_buffer; // Buffer to encrypt/decrypt to
};

} // namespace duckdb
