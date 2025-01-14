//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/operator/persistent/physical_copy_to_file.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/enums/copy_overwrite_mode.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/filename_pattern.hpp"
#include "duckdb/common/value_operations/value_operations.hpp"
#include "duckdb/execution/physical_operator.hpp"
#include "duckdb/function/copy_function.hpp"
#include "duckdb/parser/parsed_data/copy_info.hpp"
#include "duckdb/storage/storage_lock.hpp"

namespace duckdb {

//! Copy the contents of a query into a table
class PhysicalCopyToFile : public PhysicalOperator {
public:
	static constexpr const PhysicalOperatorType TYPE = PhysicalOperatorType::COPY_TO_FILE;

public:
	PhysicalCopyToFile(vector<LogicalType> types, CopyFunction function, unique_ptr<FunctionData> bind_data,
	                   idx_t estimated_cardinality);

	CopyFunction function;
	unique_ptr<FunctionData> bind_data;
	string file_path;
	bool use_tmp_file;
	FilenamePattern filename_pattern;
	string file_extension;
	CopyOverwriteMode overwrite_mode;
	bool parallel;
	bool per_thread_output;
	optional_idx file_size_bytes;
	bool rotate;
	CopyFunctionReturnType return_type;

	bool partition_output;
	bool write_partition_columns;
	vector<idx_t> partition_columns;
	vector<string> names;
	vector<LogicalType> expected_types;

public:
	// Source interface
	SourceResultType GetData(ExecutionContext &context, DataChunk &chunk, OperatorSourceInput &input) const override;

	bool IsSource() const override {
		return true;
	}

public:
	// Sink interface
	SinkResultType Sink(ExecutionContext &context, DataChunk &chunk, OperatorSinkInput &input) const override;
	SinkCombineResultType Combine(ExecutionContext &context, OperatorSinkCombineInput &input) const override;
	SinkFinalizeType Finalize(Pipeline &pipeline, Event &event, ClientContext &context,
	                          OperatorSinkFinalizeInput &input) const override;
	unique_ptr<LocalSinkState> GetLocalSinkState(ExecutionContext &context) const override;
	unique_ptr<GlobalSinkState> GetGlobalSinkState(ClientContext &context) const override;

	bool IsSink() const override {
		return true;
	}

	bool SinkOrderDependent() const override {
		return true;
	}

	bool ParallelSink() const override {
		return per_thread_output || partition_output || parallel;
	}

	static void MoveTmpFile(ClientContext &context, const string &tmp_file_path);
	static string GetNonTmpFile(ClientContext &context, const string &tmp_file_path);

	string GetTrimmedPath(ClientContext &context) const;

private:
	unique_ptr<GlobalFunctionData> CreateFileState(ClientContext &context, GlobalSinkState &sink,
	                                               StorageLockKey &global_lock) const;
};

struct PartitionWriteInfo {
    unique_ptr<GlobalFunctionData> global_state;
    idx_t active_writes = 0;
};

struct VectorOfValuesHashFunction {
    uint64_t operator()(const vector<Value> &values) const {
        hash_t result = 0;
        for (auto &val : values) {
            result ^= val.Hash();
        }
        return result;
    }
};

struct VectorOfValuesEquality {
    bool operator()(const vector<Value> &a, const vector<Value> &b) const {
        if (a.size() != b.size()) {
            return false;
        }
        for (idx_t i = 0; i < a.size(); i++) {
            if (ValueOperations::DistinctFrom(a[i], b[i])) {
                return false;
            }
        }
        return true;
    }
};

template <class T>
using vector_of_value_map_t = unordered_map<vector<Value>, T, VectorOfValuesHashFunction, VectorOfValuesEquality>;

class GlobalHivePartitionState;

class CopyToFunctionGlobalState : public GlobalSinkState {
public:
	explicit CopyToFunctionGlobalState(ClientContext &context, unique_ptr<GlobalFunctionData> global_state);

	StorageLock lock;
	atomic<idx_t> rows_copied;
	atomic<idx_t> last_file_offset;
	unique_ptr<GlobalFunctionData> global_state;
	//! Created directories
	unordered_set<string> created_directories;
	//! shared state for HivePartitionedColumnData
	shared_ptr<GlobalHivePartitionState> partition_state;
	//! File names
	vector<Value> file_names;
	//! Max open files
	idx_t max_open_files;

	void CreateDir(const string &dir_path, FileSystem &fs);
	string GetOrCreateDirectory(const vector<idx_t> &cols, const vector<string> &names, const vector<Value> &values,
	                            string path, FileSystem &fs);
	void AddFileName(const StorageLockKey &l, const string &file_name);
	void FinalizePartition(ClientContext &context, const PhysicalCopyToFile &op, PartitionWriteInfo &info);
	void FinalizePartitions(ClientContext &context, const PhysicalCopyToFile &op);
	PartitionWriteInfo &GetPartitionWriteInfo(ExecutionContext &context, const PhysicalCopyToFile &op,
	                                          const vector<Value> &values);
	void FinishPartitionWrite(PartitionWriteInfo &info);

private:
	//! The active writes per partition (for partitioned write)
	vector_of_value_map_t<unique_ptr<PartitionWriteInfo>> active_partitioned_writes;
	vector_of_value_map_t<idx_t> previous_partitions;
};
} // namespace duckdb
