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
#include "duckdb/common/counter.hpp"

using namespace duckdb;
using namespace std;

static NumericEncryptedSegment::append_function_t GetEncryptedAppendFunction(TypeId type);

NumericEncryptedSegment::NumericEncryptedSegment(BufferManager &manager, TypeId type, idx_t row_start, block_id_t block)
    : EncryptedSegment(manager, type, row_start) {
    // set up the different functions for this type of segment
    this->append_function = GetEncryptedAppendFunction(type);

    // figure out how many vectors we want to store in this block
    this->type_size = GetTypeIdSize(type);
    this->vector_size = sizeof(encrypted_vector_header_t) + type_size * STANDARD_VECTOR_SIZE;
    this->max_vector_count = Storage::BLOCK_SIZE / vector_size;

    this->block_id = block;
    this->decryption_buffer = unique_ptr<unsigned char[]>(new unsigned char[this->vector_size]);

    if (block_id == INVALID_BLOCK) {
        // no block id specified: allocate a buffer for the encrypted segment
        auto handle = manager.Allocate(Storage::BLOCK_ALLOC_SIZE);
        this->block_id = handle->block_id;
    }
}

template <class T, class OPL, class OPR>
void SelectEncrypted(SelectionVector &sel, data_ptr_t result_data, unsigned char *source, nullmask_t *source_nullmask,
            const T constantLeft, const T constantRight, idx_t &approved_tuple_count) {
    SelectionVector new_sel(approved_tuple_count);
    idx_t result_count = 0;
    if (source_nullmask->any()) {
        for (idx_t i = 0; i < approved_tuple_count; i++) {
            idx_t src_idx = sel.get_index(i);
            if (!(*source_nullmask)[src_idx] && OPL::Operation(((T *)source)[src_idx], constantLeft) &&
                OPR::Operation(((T *)source)[src_idx], constantRight)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel.set_index(result_count++, src_idx);
            }
        }
    } else {
        for (idx_t i = 0; i < approved_tuple_count; i++) {
            idx_t src_idx = sel.get_index(i);
            if (OPL::Operation(((T *)source)[src_idx], constantLeft) &&
                OPR::Operation(((T *)source)[src_idx], constantRight)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel.set_index(result_count++, src_idx);
            }
        }
    }
    sel.Initialize(new_sel);
    approved_tuple_count = result_count;
}

template <class T, class OP>
void SelectEncrypted(SelectionVector &sel, data_ptr_t result_data, unsigned char *source, nullmask_t *source_nullmask, T constant,
            idx_t &approved_tuple_count) {
    SelectionVector new_sel(approved_tuple_count);
    idx_t result_count = 0;
    if (source_nullmask->any()) {
        for (idx_t i = 0; i < approved_tuple_count; i++) {
            idx_t src_idx = sel.get_index(i);
            if (!(*source_nullmask)[src_idx] && OP::Operation(((T *)source)[src_idx], constant)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel.set_index(result_count++, src_idx);
            }
        }
    } else {
        for (idx_t i = 0; i < approved_tuple_count; i++) {
            idx_t src_idx = sel.get_index(i);
            if (OP::Operation(((T *)source)[src_idx], constant)) {
                ((T *)result_data)[src_idx] = ((T *)source)[src_idx];
                new_sel.set_index(result_count++, src_idx);
            }
        }
    }
    sel.Initialize(new_sel);
    approved_tuple_count = result_count;
}

template <class OP>
static void templated_select_encrypted_operation(SelectionVector &sel, data_ptr_t result_data, TypeId type, unsigned char *source,
                                       nullmask_t *source_mask, Value &constant, idx_t &approved_tuple_count) {
    // the inplace loops take the result as the last parameter
    switch (type) {
    case TypeId::INT8: {
        SelectEncrypted<int8_t, OP>(sel, result_data, source, source_mask, constant.value_.tinyint, approved_tuple_count);
        break;
    }
    case TypeId::INT16: {
        SelectEncrypted<int16_t, OP>(sel, result_data, source, source_mask, constant.value_.smallint, approved_tuple_count);
        ;
        break;
    }
    case TypeId::INT32: {
        SelectEncrypted<int32_t, OP>(sel, result_data, source, source_mask, constant.value_.integer, approved_tuple_count);
        break;
    }
    case TypeId::INT64: {
        SelectEncrypted<int64_t, OP>(sel, result_data, source, source_mask, constant.value_.bigint, approved_tuple_count);
        break;
    }
    case TypeId::FLOAT: {
        SelectEncrypted<float, OP>(sel, result_data, source, source_mask, constant.value_.float_, approved_tuple_count);
        break;
    }
    case TypeId::DOUBLE: {
        SelectEncrypted<double, OP>(sel, result_data, source, source_mask, constant.value_.double_, approved_tuple_count);
        break;
    }
    default:
        throw InvalidTypeException(type, "Invalid type for filter pushed down to table comparison");
    }
}

template <class OPL, class OPR>
static void templated_select_encrypted_operation_between(SelectionVector &sel, data_ptr_t result_data, TypeId type, unsigned char *source,
                                               nullmask_t *source_mask, Value &constantLeft, Value &constantRight,
                                               idx_t &approved_tuple_count) {
    // the inplace loops take the result as the last parameter
    switch (type) {
    case TypeId::INT8: {
        SelectEncrypted<int8_t, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.tinyint,
                                 constantRight.value_.tinyint, approved_tuple_count);
        break;
    }
    case TypeId::INT16: {
        SelectEncrypted<int16_t, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.smallint,
                                  constantRight.value_.smallint, approved_tuple_count);
        break;
    }
    case TypeId::INT32: {
        SelectEncrypted<int32_t, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.integer,
                                  constantRight.value_.integer, approved_tuple_count);
        break;
    }
    case TypeId::INT64: {
        SelectEncrypted<int64_t, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.bigint,
                                  constantRight.value_.bigint, approved_tuple_count);
        break;
    }
    case TypeId::FLOAT: {
        SelectEncrypted<float, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.float_,
                                constantRight.value_.float_, approved_tuple_count);
        break;
    }
    case TypeId::DOUBLE: {
        SelectEncrypted<double, OPL, OPR>(sel, result_data, source, source_mask, constantLeft.value_.double_,
                                 constantRight.value_.double_, approved_tuple_count);
        break;
    }
    default:
        throw InvalidTypeException(type, "Invalid type for filter pushed down to table comparison");
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

    auto encrypted_data = (data_ptr_t)(data + offset);

	if (tableFilter.size() == 1) {

	    if (state.current->type == TypeId::INT32)
            EnclaveExecutor::Select(encrypted_data, result, sel, approved_tuple_count, tableFilter[0].comparison_type, tableFilter[0].constant.value_.integer);
	    else if (state.current->type == TypeId::DOUBLE)
            EnclaveExecutor::Select(encrypted_data, result, sel, approved_tuple_count, tableFilter[0].comparison_type, tableFilter[0].constant.value_.double_);
        else
            throw Exception("Unimplemented type for select on encrypted segment");

	} else {

        if (state.current->type == TypeId::INT32)
            EnclaveExecutor::SelectBetween(encrypted_data, result, sel, approved_tuple_count, tableFilter[0].comparison_type, tableFilter[1].comparison_type, tableFilter[0].constant.value_.integer, tableFilter[1].constant.value_.integer);
        else if (state.current->type == TypeId::DOUBLE)
            EnclaveExecutor::SelectBetween(encrypted_data, result, sel, approved_tuple_count, tableFilter[0].comparison_type, tableFilter[1].comparison_type, tableFilter[0].constant.value_.double_, tableFilter[1].constant.value_.double_);
        else
            throw Exception("Unimplemented type for select on encrypted segment");
	}

//    SGXVector::Decrypt(result);
	// TODO EXIT SGX
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

    // Do not decrypt yet, simply store encrypted buffer inside vector for operators to figure out
    result.vector_type = VectorType::SGX_VECTOR;
    memcpy(SGXVector::GetEncryptedData(result), data + offset, count * type_size + sizeof(nullmask_t) + NONCE_BYTES);
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

    auto encrypted_data = (data_ptr_t)(data + offset);

    EnclaveExecutor::FilterFetchBaseData(encrypted_data, result, sel, approved_tuple_count, type);
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

	auto encrypted_header = (encrypted_vector_header_t*)data;
//    auto encrypted_data = data + sizeof(encrypted_vector_header_t);

    // Decrypt the vector to a decryption buffer;
    // TODO we know where in the vector we need to decrypt here so we should be able to optimize this.
    auto decryption_buffer = (data_ptr_t) this->decryption_buffer.get();
    Decrypt(decryption_buffer, encrypted_header->nullmask, vector_size - NONCE_BYTES, encrypted_header->nonce);

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
        auto encrypted_header = (encrypted_vector_header_t*) vector_buffer;
//        auto encrypted_data = (unsigned char*)vector_buffer + sizeof(encrypted_vector_header_t);

        // Decrypt existing values to encryption buffer before appending
		if (current_tuple_count > 0) {
            Decrypt(encryption_buffer, encrypted_header->nullmask, vector_size - NONCE_BYTES, encrypted_header->nonce);
		} else {
            ((nullmask_t*)encryption_buffer)->reset();
		}

		// Now perform the actual append
		append_function(stats, encryption_buffer, current_tuple_count, data, offset, append_count);

		// Encrypt appended values and set nonces
        Encrypt(encrypted_header->nullmask, encryption_buffer, vector_size - NONCE_BYTES, encrypted_header->nonce);

		count -= append_count;
		offset += append_count;
		tuple_count += append_count;
	}
	return tuple_count - initial_count;
}

//template <class T> static void update_min_max_secure(T value, T *__restrict min, T *__restrict max, SegmentStatistics &stats) {
//    if (value < *min) {
//        EnclaveExecutor::SetMinMax(stats, &value, max);
//    }
//    if (value > *max) {
//        EnclaveExecutor::SetMinMax(stats, min, &value);
//    }
//}

//template <class T>
//static void append_loop_secure(SegmentStatistics &stats, data_ptr_t target, idx_t target_offset, Vector &source, idx_t offset,
//                        idx_t count) {
//    auto &nullmask = *((nullmask_t *)target);
//
//    T min;
//    T max;
//    EnclaveExecutor::GetMinMax(stats, &min, &max);
//
////    auto min = (T *)stats.minimum.get();
////    auto max = (T *)stats.maximum.get();
//
//    VectorData adata;
//    source.Orrify(count, adata);
//
//    auto sdata = (T *)adata.data;
//    auto tdata = (T *)(target + sizeof(nullmask_t));
//    if (adata.nullmask->any()) {
//        for (idx_t i = 0; i < count; i++) {
//            auto source_idx = adata.sel->get_index(offset + i);
//            auto target_idx = target_offset + i;
//            bool is_null = (*adata.nullmask)[source_idx];
//            if (is_null) {
//                nullmask[target_idx] = true;
//                stats.has_null = true;
//            } else {
//                update_min_max_secure(sdata[source_idx], &min, &max, stats);
//                tdata[target_idx] = sdata[source_idx];
//            }
//        }
//    } else {
//        for (idx_t i = 0; i < count; i++) {
//            auto source_idx = adata.sel->get_index(offset + i);
//            auto target_idx = target_offset + i;
//            update_min_max_secure(sdata[source_idx], &min, &max, stats);
//            tdata[target_idx] = sdata[source_idx];
//        }
//    }
//}


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