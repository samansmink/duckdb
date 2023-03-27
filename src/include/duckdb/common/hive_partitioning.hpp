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
#include "duckdb/optimizer/filter_combiner.hpp"
#include "duckdb/optimizer/statistics_propagator.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "re2/re2.h"

#include <sstream>
#include <iostream>

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
	//! the limit for this partition
	static constexpr idx_t PARTITION_TUPLE_LIMIT {10};

	//! the amount of tuples that have been written globally into this partition.
	atomic<idx_t> written {0};
	//! the total amount of tuples that will be written into this partition
	atomic<idx_t> started {0};

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

			if (current > PARTITION_TUPLE_LIMIT) {
				return RegisterWriteResult::IS_FLUSHING;
			}

			if (started.compare_exchange_weak(current, current + count)) {
				if (current + count > PARTITION_TUPLE_LIMIT) {
					return RegisterWriteResult::SHOULD_FLUSH;
				} else {
					return RegisterWriteResult::SUCCESS;
				}
			}
		}
	}
};

class HivePartitionedColumnData;

//! class shared between HivePartitionColumnData classes that synchronizes partition discovery between threads.
//! each HivePartitionedColumnData will hold a local copy of the key->partition map
class GlobalHivePartitionState {
public:
	mutex lock;
	hive_partition_map_t partition_map;

	//! Used for incremental updating local copies of the partition map;
	std::vector<hive_partition_map_t::const_iterator> partitions;

	//! Optionally, we can enable streaming mode
	bool streaming_mode = true;

	// maps partition_idx to VersionInfo, needs to be shared because threads need their own thread-local copy of this
	// vector to be able to access it in a thread safe way
	vector<shared_ptr<PartitionVersionStats>> partition_info;

	// to prevent every thread from refreshing its entire partition map on every sync, we have a list of all flushes that
	// threads can apply to their local
	// TODO: can we do better than this?
	vector<std::pair<HivePartitionKey, idx_t>> updates;

	// TODO: raw pointers here is probably ugly / error-prone?
	vector<HivePartitionedColumnData*> data_collections;
};

//! Callback for flushes
//typedef void (*hive_partition_flush_callback_t)(HivePartitionKey& key, unique_ptr<ColumnDataCollection> data);
typedef std::function<void(HivePartitionKey& key, idx_t current_idx, unique_ptr<ColumnDataCollection> data)> hive_partition_flush_callback_t;

class HivePartitionedColumnData : public PartitionedColumnData {
public:
	HivePartitionedColumnData(ClientContext &context, vector<LogicalType> types, vector<idx_t> partition_by_cols,
	                          shared_ptr<GlobalHivePartitionState> global_state_p = nullptr)
	    : PartitionedColumnData(PartitionedColumnDataType::HIVE, context, std::move(types)),
	      global_state(std::move(global_state_p)), group_by_columns(partition_by_cols) {

		if (global_state) {
			global_state->data_collections.push_back(this);
		}
	}
	HivePartitionedColumnData(const HivePartitionedColumnData &other);
	void ComputePartitionIndices(PartitionedColumnDataAppendState &state, DataChunk &input) override;

	//! Reverse lookup map to reconstruct keys from a partition id
	std::map<idx_t, const HivePartitionKey *> GetReverseMap();

	//! Flushes all partitions, flushing the partitions for all threads globally. To be done at end
	void FlushAll();

	//! Flushes a partition from the PCD for ALL threads
	hive_partition_flush_callback_t flush_callback;

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

	//!
	void FlushPartition(HivePartitionKey& key, idx_t current_partition_id, idx_t count);

	//! This function will ensure a key is remapped to a new partition_id to ensure other threads can continue writing
	//! tuples with that key to a new partition_idx; TODO should key be copied?
	idx_t RemapPartition(HivePartitionKey key, PartitionedColumnDataAppendState &state);
	//! This function will try to claim write permission on original_idx. If it fails, it will either allocate a new
	//! partition id for the key, or wait for another thread to do so.
	idx_t RegisterWrite(HivePartitionKey& key, idx_t original_idx, idx_t count, idx_t waiting, PartitionedColumnDataAppendState& state);

	void FinishWrite(idx_t partition_index, idx_t count) override {
		if (global_state) {
			global_state->partition_info[partition_index]->written += count;
		}
	}

	vector<shared_ptr<PartitionVersionStats>> local_partition_info;

	idx_t applied_partition_update_idx = 0;
};

} // namespace duckdb
