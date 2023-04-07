//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/hive_partitioning.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/types/partitioned_column_data.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/optimizer/filter_combiner.hpp"
#include "duckdb/optimizer/statistics_propagator.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "re2/re2.h"

#include <sstream>
#include <iostream>
#include <condition_variable>

namespace duckdb {

class HivePartitioning {
public:
	//! Parse a filename that follows the hive partitioning scheme
	DUCKDB_API static std::map<string, string> Parse(string &filename);
	DUCKDB_API static std::map<string, string> Parse(string &filename, duckdb_re2::RE2 &regex);
	//! Prunes a list of filenames based on a set of filters, can be used by TableFunctions in the
	//! pushdown_complex_filter function to skip files with filename-based filters. Also removes the filters that always
	//! evaluate to true.
	DUCKDB_API static void ApplyFiltersToFileList(ClientContext &context, vector<string> &files,
	                                              vector<unique_ptr<Expression>> &filters,
	                                              unordered_map<string, column_t> &column_map, idx_t table_index,
	                                              bool hive_enabled, bool filename_enabled);

	//! Returns the compiled regex pattern to match hive partitions
	DUCKDB_API static const string REGEX_STRING;
};

struct HivePartitionKey {
	//! Columns by which we want to partition
	vector<Value> values;
	//! Precomputed hash of values
	hash_t hash;

	struct Hash {
		std::size_t operator()(const HivePartitionKey &k) const {
			return k.hash;
		}
	};

	struct Equality {
		bool operator()(const HivePartitionKey &a, const HivePartitionKey &b) const {
			if (a.values.size() != b.values.size()) {
				return false;
			}
			for (idx_t i = 0; i < a.values.size(); i++) {
				if (!Value::NotDistinctFrom(a.values[i], b.values[i])) {
					return false;
				}
			}
			return true;
		}
	};
};

//! To allow flushing, we will use the following trick:
//! - a partition in the cdc is not actually a partition, but a single flush of a partition.

//! Two layer lookup
// 1: map<HivePartitionKey, idx_t> partition_map KEY -> PartitionIndex (same as the current partition indices, but idx it not used directly)
// 2: map<idx_t,idx_t> partition_version_map PartitionIndex -> VersionedPartitionIndex (VersionedPartitionIndex is how it's seen by the base CDC) DO WE NEED THIS THOUGH?
//! When in ComputePartitionIndices we look up a partition key, we need to check if its version matches
//!

// For all partitionIndices we find in ComputePartitionIndices:
// - check if partition_end < limit
// 		- if it is, update it with our count
//			- if our count does not exceed the limit, we gud
//			- if it does, we need to create the next version of this partition AND flush the existing one.
//		- if it is not, we need to update the entry (how?)

// How to flush the partition version:
// - create a new partition so that other threads can continue writing
//		- lock the global_state
//			- A new partition (both for a new key and a new existing key version )
//		- update partition_version_map for our partition
//		- call GrowAllocators to ensure the new versioned_partition is available
//		- call SynchronizeLocalMap() to ensure we're good to go locally

//! Maps hive partitions to partition_ids
typedef unordered_map<HivePartitionKey, idx_t, HivePartitionKey::Hash, HivePartitionKey::Equality> hive_partition_map_t;

//! The version stats allow setting limits to how full a partition can actually be
struct PartitionVersionStats {
	PartitionVersionStats(idx_t logical_index_p, idx_t limit) : logical_index(logical_index_p), limit(limit) {};
	PartitionVersionStats() = delete;

	//! the amount of tuples that have been written globally into this partition.
	atomic<idx_t> written {0};
	//! the total amount of tuples that will be written into this partition
	atomic<idx_t> started {0};

	//! logical index of the physical partition
	idx_t logical_index;
	const idx_t limit;

	enum class RegisterWriteResult {
		//! Successfully registered the write, partition is cleared for writing
		SUCCESS,
		//! Some other thread is flushing this partition, we cannot write to it
		IS_FLUSHING,
		//! This thread can write to the partition, but MUST flush this partition globally for all threads
		SHOULD_FLUSH
	};

	//! Synchronization primitive to ensure threads stop writing to a partition when its full, and to ensure that
	//! one thread is assigned the task of flushing a partition.
	RegisterWriteResult RegisterWrite (idx_t count) {
		while(true) {
			auto current = started.load();

			if (current > limit) {
				return RegisterWriteResult::IS_FLUSHING;
			}

			if (started.compare_exchange_weak(current, current + count)) {
				if (current + count > limit) {
					return RegisterWriteResult::SHOULD_FLUSH;
				} else {
					return RegisterWriteResult::SUCCESS;
				}
			}
		}
	}

	RegisterWriteResult RegisterFinalize() {
		while(true) {
			auto current = started.load();

			if (current > limit) {
				return RegisterWriteResult::IS_FLUSHING;
			}

			if (started.compare_exchange_weak(current, current + limit)) {
				return RegisterWriteResult::SHOULD_FLUSH;
			}
		}
	}
};

class HivePartitionedColumnData;
class HivePartitionedColumnDataManager;

//! class shared between HivePartitionColumnData classes that synchronizes partition discovery between threads.
//! each HivePartitionedColumnData will hold a local copy of the key->partition map
class GlobalHivePartitionState {
public:
	mutex lock;
	//! Maps key to logical partition idx;
	hive_partition_map_t partition_map;

	//! Used for incremental updating local copies of the partition map;
	std::vector<hive_partition_map_t::const_iterator> partitions;

	//! maps physical partition idx to VersionInfo, needs to be shared because threads need their own thread-local
	//! copy of this vector to be able to access it in a thread safe way.
	vector<shared_ptr<PartitionVersionStats>> partition_info;

	//! Updates to partitions are stored as updates to allow efficiently synchronizing local copies of the version map
	vector<std::pair<idx_t, idx_t>> version_map_updates;

	//! Maps logical partition idx to physical partition idx
	vector<idx_t> version_map;

//	vector<HivePartitionedColumnData*> data_collections;

	idx_t total_writers = 0;
	idx_t finished_writers = 0;
	std::condition_variable writer_cv;

	HivePartitionedColumnDataManager* manager;
};

//! Callback for flushes
//typedef void (*hive_partition_flush_callback_t)(HivePartitionKey& key, unique_ptr<ColumnDataCollection> data);
typedef std::function<void(const HivePartitionKey& key, idx_t logical_idx, unique_ptr<ColumnDataCollection> data)> hive_partition_flush_callback_t;

class HivePartitionedColumnData : public PartitionedColumnData {
public:
	HivePartitionedColumnData(ClientContext &context, vector<LogicalType> types, vector<idx_t> partition_by_cols,
	                          shared_ptr<GlobalHivePartitionState> global_state_p = nullptr)
	    : PartitionedColumnData(PartitionedColumnDataType::HIVE, context, std::move(types)),
	      global_state(std::move(global_state_p)), group_by_columns(partition_by_cols) {

		if (global_state) {
			unique_lock<mutex> lck (global_state->lock);
			global_state->total_writers++;
		}
	}
	HivePartitionedColumnData(const HivePartitionedColumnData &other);
	void ComputePartitionIndices(PartitionedColumnDataAppendState &state, DataChunk &input) override;

	//! Reverse lookup map to reconstruct keys from a partition id
	std::map<idx_t, const HivePartitionKey *> GetReverseMap();

	//! Flushes the append state, then will start cooperatively flushing all partitions.
	void Finalize(PartitionedColumnDataAppendState& state);

	//! Flushes a partition from the PCD for ALL threads
	hive_partition_flush_callback_t flush_callback;

	unique_ptr<HivePartitionedColumnData> CreateShared() {
		return make_unique<HivePartitionedColumnData>((HivePartitionedColumnData &)*this);
	}

	//! Ensures there are enough allocators, append states and partitions
	void Grow(PartitionedColumnDataAppendState &state) {
		{
			unique_lock<mutex>(global_state->lock);
			SynchronizeLocalMap();
		}
		GrowAllocators();
		GrowAppendState(state);
		GrowPartitions(state);
	}

	void Sync(PartitionedColumnDataAppendState &state) {
		{
			unique_lock<mutex>(global_state->lock);
			SynchronizeLocalMap();
		}
		Grow(state);
	}
protected:
	//! Create allocators for all currently registered partitions
	void GrowAllocators();
	//! Create append states for all currently registered partitions
	void GrowAppendState(PartitionedColumnDataAppendState &state);
	//! Create and initialize partitions for all currently registered partitions
	void GrowPartitions(PartitionedColumnDataAppendState &state);
	//! Register a newly discovered partition
	idx_t RegisterNewPartition(HivePartitionKey key, PartitionedColumnDataAppendState &state);
	//! Copy the newly added entries in the global_state.map to the local_partition_map (requires lock!)
	void SynchronizeLocalMap();

	//! Shared HivePartitionedColumnData should always have a global state to allow parallel key discovery
	shared_ptr<GlobalHivePartitionState> global_state;
	//! Thread-local copy of the partition map
	hive_partition_map_t local_partition_map;
	//! The columns that make up the key
	vector<idx_t> group_by_columns;

	//! Flushes the data from the physical partition. Not that this is only safe to call when the correct RegisterWrite
	//! result has been given to this thread
	void FlushPartition(idx_t logical_partition_index, idx_t physical_partition_index, idx_t count);
	//! Ensures a new physical partition is made available globally
	void AssignNewPhysicalPartition(idx_t logical_partition_index, PartitionedColumnDataAppendState& state);
	idx_t RegisterWrite(PartitionedColumnDataAppendState& state, idx_t logical_partition_index, idx_t count) override;
	void FinishWrite(idx_t logical_index, idx_t physical_index, idx_t count) override;

	// Maps logical partition idx to physical partition idx
	vector<idx_t> local_version_map;

	// Partition info for each physical partition
	vector<shared_ptr<PartitionVersionStats>> local_partition_info;
	idx_t applied_partition_update_idx = 0;
};


//! For streaming PartitionedColumnData, we need a global manager class to ensure correct ownership
class HivePartitionedColumnDataManager {
public:
	HivePartitionedColumnDataManager(ClientContext &context, vector<LogicalType> types, vector<idx_t> partition_by_cols,
	                                 shared_ptr<GlobalHivePartitionState> global_state_p = nullptr) : context(context),
	      types(types), partition_by_cols(partition_by_cols), global_state(global_state_p){

		if (global_state->manager) {
			throw InternalException("State Already registered to a manager");
		}

		global_state->manager = this;
	};

	HivePartitionedColumnData* CreateNewPartitionedColumnData() {
		if (column_data.empty()) {
			column_data.emplace_back(make_unique<HivePartitionedColumnData>(context, types, partition_by_cols, global_state));
		} else {
			column_data.emplace_back(column_data.back().get()->CreateShared());
		}

		return column_data.back().get();
	}


	vector<unique_ptr<HivePartitionedColumnData>> column_data;

	idx_t GetPartitionTupleLimit() {
		return context.config.partitioned_copy_max_partition_size;
	}

protected:
	ClientContext &context;
	vector<LogicalType> types;
	vector<idx_t> partition_by_cols;
	shared_ptr<GlobalHivePartitionState> global_state;
};

} // namespace duckdb
