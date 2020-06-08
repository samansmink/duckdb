#include "duckdb/common/operator/comparison_operators.hpp"
#include "duckdb/storage/numeric_encrypted_segment.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/storage/table/append_state.hpp"
#include "duckdb/transaction/update_info.hpp"
#include "duckdb/transaction/transaction.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/storage/data_table.hpp"
#include "duckdb/common/crypto.hpp"

using namespace duckdb;
using namespace std;

static NumericEncryptedSegment::append_function_t GetEncryptedAppendFunction(TypeId type);

NumericEncryptedSegment::NumericEncryptedSegment(BufferManager &manager, TypeId type, idx_t row_start, block_id_t block)
    : EncryptedSegment(manager, type, row_start) {
    // set up the different functions for this type of segment
    this->append_function = GetEncryptedAppendFunction(type);

    // figure out how many vectors we want to store in this block
    this->type_size = GetTypeIdSize(type);
    this->vector_size = sizeof(nullmask_t) + NONCE_BYTES + type_size * STANDARD_VECTOR_SIZE;
    this->max_vector_count = Storage::BLOCK_SIZE / vector_size;

    this->block_id = block;

    this->decryption_buffer = unique_ptr<unsigned char[]>(new unsigned char[this->vector_size]);

    if (block_id == INVALID_BLOCK) {
        // no block id specified: allocate a buffer for the encrypted segment
        auto handle = manager.Allocate(Storage::BLOCK_ALLOC_SIZE);
        this->block_id = handle->block_id;
        // initialize nullmasks to 0 for all vectors
        for (idx_t i = 0; i < max_vector_count; i++) {
            auto mask = (nullmask_t *)(handle->node->buffer + (i * vector_size));
            mask->reset();
        }
    }
}

void NumericEncryptedSegment::Select(ColumnScanState &state, Vector &result, SelectionVector &sel, idx_t &approved_tuple_count,
                            vector<TableFilter> &tableFilter) {
	auto vector_index = state.vector_index;
	assert(vector_index < max_vector_count);
	assert(vector_index * STANDARD_VECTOR_SIZE <= tuple_count);

	// pin the buffer for this segment
	auto handle = manager.Pin(block_id);
	auto data = handle->node->buffer;
	auto offset = vector_index * vector_size;

    auto encrypted_data = data + offset + NONCE_BYTES;
    auto nonce = (unsigned char*)(data + offset);

    // Decrypt the vector to a decryption buffer;
    auto decryption_buffer = (data_ptr_t) this->decryption_buffer.get();

    Decrypt(decryption_buffer, encrypted_data, this->vector_size - NONCE_BYTES, nonce);

    auto source_nullmask = (nullmask_t *)(decryption_buffer);
    auto source_data = decryption_buffer + sizeof(nullmask_t);

	if (tableFilter.size() == 1) {
		switch (tableFilter[0].comparison_type) {
		case ExpressionType::COMPARE_EQUAL: {
            templated_select_operation<Equals>(sel, result, state.current->type, source_data, source_nullmask,
			                                   tableFilter[0].constant, approved_tuple_count);
			break;
		}
		case ExpressionType::COMPARE_LESSTHAN: {
            templated_select_operation<LessThan>(sel, result, state.current->type, source_data, source_nullmask,
			                                     tableFilter[0].constant, approved_tuple_count);
			break;
		}
		case ExpressionType::COMPARE_GREATERTHAN: {
            templated_select_operation<GreaterThan>(sel, result, state.current->type, source_data, source_nullmask,
			                                        tableFilter[0].constant, approved_tuple_count);
			break;
		}
		case ExpressionType::COMPARE_LESSTHANOREQUALTO: {
            templated_select_operation<LessThanEquals>(sel, result, state.current->type, source_data, source_nullmask,
			                                           tableFilter[0].constant, approved_tuple_count);
			break;
		}
		case ExpressionType::COMPARE_GREATERTHANOREQUALTO: {
            templated_select_operation<GreaterThanEquals>(sel, result, state.current->type, source_data,
			                                              source_nullmask, tableFilter[0].constant,
			                                              approved_tuple_count);
			break;
		}
		default:
			throw NotImplementedException("Unknown comparison type for filter pushed down to table!");
		}
	} else {
		assert(tableFilter[0].comparison_type == ExpressionType::COMPARE_GREATERTHAN ||
		       tableFilter[0].comparison_type == ExpressionType::COMPARE_GREATERTHANOREQUALTO);
		assert(tableFilter[1].comparison_type == ExpressionType::COMPARE_LESSTHAN ||
		       tableFilter[1].comparison_type == ExpressionType::COMPARE_LESSTHANOREQUALTO);

		if (tableFilter[0].comparison_type == ExpressionType::COMPARE_GREATERTHAN) {
			if (tableFilter[1].comparison_type == ExpressionType::COMPARE_LESSTHAN) {
                templated_select_operation_between<GreaterThan, LessThan>(
				    sel, result, state.current->type, source_data, source_nullmask, tableFilter[0].constant,
				    tableFilter[1].constant, approved_tuple_count);
			} else {
                templated_select_operation_between<GreaterThan, LessThanEquals>(
				    sel, result, state.current->type, source_data, source_nullmask, tableFilter[0].constant,
				    tableFilter[1].constant, approved_tuple_count);
			}
		} else {
			if (tableFilter[1].comparison_type == ExpressionType::COMPARE_LESSTHAN) {
                templated_select_operation_between<GreaterThanEquals, LessThan>(
				    sel, result, state.current->type, source_data, source_nullmask, tableFilter[0].constant,
				    tableFilter[1].constant, approved_tuple_count);
			} else {
                templated_select_operation_between<GreaterThanEquals, LessThanEquals>(
				    sel, result, state.current->type, source_data, source_nullmask, tableFilter[0].constant,
				    tableFilter[1].constant, approved_tuple_count);
			}
		}
	}
}

//===--------------------------------------------------------------------===//
// Fetch base data
//===--------------------------------------------------------------------===//
void NumericEncryptedSegment::FetchBaseData(ColumnScanState &state, idx_t vector_index, Vector &result) {
	assert(vector_index < max_vector_count);
	assert(vector_index * STANDARD_VECTOR_SIZE <= tuple_count);

	// pin the buffer for this segment
	auto handle = manager.Pin(block_id);
	auto data = handle->node->buffer;

	auto offset = vector_index * vector_size;

	idx_t count = GetVectorCount(vector_index);

    auto encrypted_data = data + offset + NONCE_BYTES;
    auto nonce = (unsigned char*)(data + offset);

    // Decrypt the vector to a decryption buffer;
    auto decryption_buffer = (data_ptr_t) this->decryption_buffer.get();

    Decrypt(decryption_buffer, encrypted_data, this->vector_size - NONCE_BYTES, nonce);

	// fetch the nullmask and copy the data from the base table
	result.vector_type = VectorType::FLAT_VECTOR;
	auto source_nullmask = (nullmask_t *)(decryption_buffer);
	FlatVector::SetNullmask(result, *source_nullmask);
	memcpy(FlatVector::GetData(result), decryption_buffer + sizeof(nullmask_t), count * type_size);
}

void NumericEncryptedSegment::FetchUpdateData(ColumnScanState &state, Transaction &transaction, UpdateInfo *version,
                                     Vector &result) {
	throw new NotImplementedException("FetchUpdateData not implemented on encrypted segment");
}

void NumericEncryptedSegment::FilterFetchBaseData(ColumnScanState &state, Vector &result, SelectionVector &sel,
                                         idx_t &approved_tuple_count) {
	auto vector_index = state.vector_index;
	assert(vector_index < max_vector_count);
	assert(vector_index * STANDARD_VECTOR_SIZE <= tuple_count);

	// pin the buffer for this segment
	auto handle = manager.Pin(block_id);
	auto data = handle->node->buffer;
	auto offset = vector_index * vector_size;

    auto encrypted_data = data + offset + NONCE_BYTES;
    auto nonce = (unsigned char*)(data + offset);

    // Decrypt the vector to a decryption buffer;
    auto decryption_buffer = (data_ptr_t) this->decryption_buffer.get();

    Decrypt(decryption_buffer, encrypted_data, this->vector_size - NONCE_BYTES, nonce);

	auto source_nullmask = (nullmask_t *)(decryption_buffer);
	auto source_data = decryption_buffer + sizeof(nullmask_t);

	// fetch the nullmask and copy the data from the base table
	result.vector_type = VectorType::FLAT_VECTOR;
	auto result_data = FlatVector::GetData(result);
	nullmask_t result_nullmask;
	// the inplace loops take the result as the last parameter
	switch (type) {
	case TypeId::BOOL:
	case TypeId::INT8: {
        templated_assignment<int8_t>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                             approved_tuple_count);
		break;
	}
	case TypeId::INT16: {
        templated_assignment<int16_t>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                              approved_tuple_count);
		break;
	}
	case TypeId::INT32: {
        templated_assignment<int32_t>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                              approved_tuple_count);
		break;
	}
	case TypeId::INT64: {
        templated_assignment<int64_t>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                              approved_tuple_count);
		break;
	}
	case TypeId::FLOAT: {
        templated_assignment<float>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                            approved_tuple_count);
		break;
	}
	case TypeId::DOUBLE: {
        templated_assignment<double>(sel, source_data, result_data, *source_nullmask, result_nullmask,
		                             approved_tuple_count);
		break;
	}
	default:
		throw InvalidTypeException(type, "Invalid type for filter scan");
	}

	FlatVector::SetNullmask(result, result_nullmask);
}

//===--------------------------------------------------------------------===//
// Fetch
//===--------------------------------------------------------------------===//
void NumericEncryptedSegment::FetchRow(ColumnFetchState &state, Transaction &transaction, row_t row_id, Vector &result,
                              idx_t result_idx) {
	auto read_lock = lock.GetSharedLock();
	auto handle = manager.Pin(block_id);

	// get the vector index
	idx_t vector_index = row_id / STANDARD_VECTOR_SIZE;
	idx_t id_in_vector = row_id - vector_index * STANDARD_VECTOR_SIZE;
	assert(vector_index < max_vector_count);

	// first fetch the data from the base table
	auto data = handle->node->buffer + vector_index * vector_size;

    auto encrypted_data = data + NONCE_BYTES;
    auto nonce = (unsigned char*)(data);

    // Decrypt the vector to a decryption buffer;
    auto decryption_buffer = (data_ptr_t) this->decryption_buffer.get();

    Decrypt(decryption_buffer, encrypted_data, this->vector_size - NONCE_BYTES, nonce);

	auto &nullmask = *((nullmask_t *)(decryption_buffer));
	auto vector_ptr = decryption_buffer + sizeof(nullmask_t);

	FlatVector::SetNull(result, result_idx, nullmask[id_in_vector]);
	memcpy(FlatVector::GetData(result) + result_idx * type_size, vector_ptr + id_in_vector * type_size, type_size);
	if (versions && versions[vector_index]) {
        throw new NotImplementedException("Versions found in encrypted segment where updating is not supported");
	}
}

//===--------------------------------------------------------------------===//
// Update
//===--------------------------------------------------------------------===//
void NumericEncryptedSegment::Update(ColumnData &column_data, SegmentStatistics &stats, Transaction &transaction, Vector &update,
                            row_t *ids, idx_t count, idx_t vector_index, idx_t vector_offset, UpdateInfo *node) {
    throw new NotImplementedException("FetchUpdateData not implemented on encrypted segment");
}

void NumericEncryptedSegment::RollbackUpdate(UpdateInfo *info) {
    throw new NotImplementedException("FetchUpdateData not implemented on encrypted segment");
}

//===--------------------------------------------------------------------===//
// Append
//===--------------------------------------------------------------------===//
idx_t NumericEncryptedSegment::Append(SegmentStatistics &stats, Vector &data, idx_t offset, idx_t count) {
	assert(data.type == type);
	auto handle = manager.Pin(block_id);

    auto encryption_buffer = (data_ptr_t) this->decryption_buffer.get();

	idx_t initial_count = tuple_count;
	while (count > 0) {
		// get the vector index of the vector to append to and see how many tuples we can append to that vector
		idx_t vector_index = tuple_count / STANDARD_VECTOR_SIZE;
		if (vector_index == max_vector_count) {
			break;
		}
		idx_t current_tuple_count = tuple_count - vector_index * STANDARD_VECTOR_SIZE;
		idx_t append_count = std::min(STANDARD_VECTOR_SIZE - current_tuple_count, count);

        auto vector_buffer = handle->node->buffer + vector_size * vector_index;

		if (current_tuple_count > 0) {
            Decrypt(encryption_buffer, vector_buffer + NONCE_BYTES, this->vector_size - NONCE_BYTES, vector_buffer);
		} else {
            memcpy(encryption_buffer, vector_buffer + NONCE_BYTES, sizeof(nullmask_t));
		}

		// now perform the actual append
		append_function(stats, encryption_buffer, current_tuple_count, data, offset,
		                append_count);

        Encrypt(vector_buffer + NONCE_BYTES, encryption_buffer, this->vector_size - NONCE_BYTES, vector_buffer);


		count -= append_count;
		offset += append_count;
		tuple_count += append_count;
	}
	return tuple_count - initial_count;
}

// TODO redefinition?
//template <class T> static void update_min_max(T value, T *__restrict min, T *__restrict max);

static NumericEncryptedSegment::append_function_t GetEncryptedAppendFunction(TypeId type) {
	switch (type) {
	case TypeId::BOOL:
	case TypeId::INT8:
		return append_loop<int8_t>;
	case TypeId::INT16:
		return append_loop<int16_t>;
	case TypeId::INT32:
		return append_loop<int32_t>;
	case TypeId::INT64:
		return append_loop<int64_t>;
	case TypeId::FLOAT:
		return append_loop<float>;
	case TypeId::DOUBLE:
		return append_loop<double>;
	default:
		throw NotImplementedException("Unimplemented type for encrypted segment");
	}
}