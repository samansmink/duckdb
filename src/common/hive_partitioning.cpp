#include "duckdb/common/hive_partitioning.hpp"
#include "duckdb/optimizer/statistics_propagator.hpp"
#include "duckdb/planner/table_filter.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/optimizer/filter_combiner.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "re2/re2.h"

#include <chrono>
#include <thread>

namespace duckdb {

static unordered_map<column_t, string> GetKnownColumnValues(string &filename,
                                                            unordered_map<string, column_t> &column_map,
                                                            duckdb_re2::RE2 &compiled_regex, bool filename_col,
                                                            bool hive_partition_cols) {
	unordered_map<column_t, string> result;

	if (filename_col) {
		auto lookup_column_id = column_map.find("filename");
		if (lookup_column_id != column_map.end()) {
			result[lookup_column_id->second] = filename;
		}
	}

	if (hive_partition_cols) {
		auto partitions = HivePartitioning::Parse(filename, compiled_regex);
		for (auto &partition : partitions) {
			auto lookup_column_id = column_map.find(partition.first);
			if (lookup_column_id != column_map.end()) {
				result[lookup_column_id->second] = partition.second;
			}
		}
	}

	return result;
}

// Takes an expression and converts a list of known column_refs to constants
static void ConvertKnownColRefToConstants(unique_ptr<Expression> &expr,
                                          unordered_map<column_t, string> &known_column_values, idx_t table_index) {
	if (expr->type == ExpressionType::BOUND_COLUMN_REF) {
		auto &bound_colref = (BoundColumnRefExpression &)*expr;

		// This bound column ref is for another table
		if (table_index != bound_colref.binding.table_index) {
			return;
		}

		auto lookup = known_column_values.find(bound_colref.binding.column_index);
		if (lookup != known_column_values.end()) {
			expr = make_unique<BoundConstantExpression>(Value(lookup->second));
		}
	} else {
		ExpressionIterator::EnumerateChildren(*expr, [&](unique_ptr<Expression> &child) {
			ConvertKnownColRefToConstants(child, known_column_values, table_index);
		});
	}
}

// matches hive partitions in file name. For example:
// 	- s3://bucket/var1=value1/bla/bla/var2=value2
//  - http(s)://domain(:port)/lala/kasdl/var1=value1/?not-a-var=not-a-value
//  - folder/folder/folder/../var1=value1/etc/.//var2=value2
const string HivePartitioning::REGEX_STRING = "[\\/\\\\]([^\\/\\?\\\\]+)=([^\\/\\n\\?\\\\]+)";

std::map<string, string> HivePartitioning::Parse(string &filename, duckdb_re2::RE2 &regex) {
	std::map<string, string> result;
	duckdb_re2::StringPiece input(filename); // Wrap a StringPiece around it

	string var;
	string value;
	while (RE2::FindAndConsume(&input, regex, &var, &value)) {
		result.insert(std::pair<string, string>(var, value));
	}
	return result;
}

std::map<string, string> HivePartitioning::Parse(string &filename) {
	duckdb_re2::RE2 regex(REGEX_STRING);
	return Parse(filename, regex);
}

// TODO: this can still be improved by removing the parts of filter expressions that are true for all remaining files.
//		 currently, only expressions that cannot be evaluated during pushdown are removed.
void HivePartitioning::ApplyFiltersToFileList(ClientContext &context, vector<string> &files,
                                              vector<unique_ptr<Expression>> &filters,
                                              unordered_map<string, column_t> &column_map, idx_t table_index,
                                              bool hive_enabled, bool filename_enabled) {
	vector<string> pruned_files;
	vector<bool> have_preserved_filter(filters.size(), false);
	vector<unique_ptr<Expression>> pruned_filters;
	duckdb_re2::RE2 regex(REGEX_STRING);

	if ((!filename_enabled && !hive_enabled) || filters.empty()) {
		return;
	}

	for (idx_t i = 0; i < files.size(); i++) {
		auto &file = files[i];
		bool should_prune_file = false;
		auto known_values = GetKnownColumnValues(file, column_map, regex, filename_enabled, hive_enabled);

		FilterCombiner combiner(context);

		for (idx_t j = 0; j < filters.size(); j++) {
			auto &filter = filters[j];
			unique_ptr<Expression> filter_copy = filter->Copy();
			ConvertKnownColRefToConstants(filter_copy, known_values, table_index);
			// Evaluate the filter, if it can be evaluated here, we can not prune this filter
			Value result_value;

			if (!filter_copy->IsScalar() || !filter_copy->IsFoldable() ||
			    !ExpressionExecutor::TryEvaluateScalar(context, *filter_copy, result_value)) {
				// can not be evaluated only with the filename/hive columns added, we can not prune this filter
				if (!have_preserved_filter[j]) {
					pruned_filters.emplace_back(filter->Copy());
					have_preserved_filter[j] = true;
				}
			} else if (!result_value.GetValue<bool>()) {
				// filter evaluates to false
				should_prune_file = true;
			}

			// Use filter combiner to determine that this filter makes
			if (!should_prune_file && combiner.AddFilter(std::move(filter_copy)) == FilterResult::UNSATISFIABLE) {
				should_prune_file = true;
			}
		}

		if (!should_prune_file) {
			pruned_files.push_back(file);
		}
	}

	D_ASSERT(filters.size() >= pruned_filters.size());

	filters = std::move(pruned_filters);
	files = std::move(pruned_files);
}

HivePartitionedColumnData::HivePartitionedColumnData(const HivePartitionedColumnData &other)
    : PartitionedColumnData(other) {
	// Synchronize to ensure consistency of shared partition map
	if (other.global_state) {
		global_state = other.global_state;
		unique_lock<mutex> lck(global_state->lock);
		global_state->data_collections.push_back(this);
		SynchronizeLocalMap();
	}
}

void HivePartitionedColumnData::FlushPartition(HivePartitionKey& key, idx_t current_partition_id, idx_t my_count) {
	//! - busy wait for other threads to finish writing to the old partition (wait for PartitionVersionStats.started = PartitionVersionStats.written)
	//! - merge columndatacollections from all threads, call flush_callback
	//! - free shared allocator for partition

	auto& partition_info = local_partition_info[current_partition_id];

	// busy wait for other threads to finish writing to this partition.
	while (partition_info->started - partition_info->written > my_count) {
	}

	// Merge partitions from all threads
	auto& combined = global_state->data_collections[0]->partitions[current_partition_id];
	for (idx_t i = 1; i < global_state->data_collections.size(); i++) {
		auto& to_combine = global_state->data_collections[i]->partitions[current_partition_id];
		combined->Combine(*to_combine);
		combined = nullptr; // TODO: this is reset now for dev/debug purposes, we may want to keep it since its empty anyway and we could reuse it
	}

	if (!flush_callback) {
		throw InternalException("Flush called on HivePartitionedColumnData without flush callback");
	}

	flush_callback(key, std::move(combined));
}

void HivePartitionedColumnData::FlushAll() {
	// TODO: go over partitions one by one, trying to claim them and flushing them
}

idx_t HivePartitionedColumnData::RemapPartition(HivePartitionKey key, PartitionedColumnDataAppendState &state)  {
	if (global_state) {
		idx_t new_idx;

		// Synchronize Global state with our local state with any new partitions from other threads
		{
			unique_lock<mutex> lck_gstate(global_state->lock);

			new_idx = global_state->partition_info.size(); // careful, partition_info size used as partition count!
			// Insert into global map, or return partition if already present
			auto res = global_state->partition_map[key] = new_idx;
			// Create partition stats for the new partition
			global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>());
			SynchronizeLocalMap();
		}

		GrowAllocators();

		// Grow local partition data
		GrowAppendState(state);
		GrowPartitions(state);

		return new_idx;
	} else {
		throw NotImplementedException("Remapping a partition without global_state makes no sense i think?");
	}
}

// This function will try to claim write permission on original_idx. It may
idx_t HivePartitionedColumnData::RegisterWrite(HivePartitionKey& key, idx_t original_idx, idx_t count) {
	idx_t current_partition_idx = original_idx;
	auto current_partition_info = local_partition_info[original_idx];
	bool got_partition = false;

	while (!got_partition) {
		auto res = current_partition_info->RegisterWrite(count);

		if (res == PartitionVersionStats::RegisterWriteResult::IS_FLUSHING) {
			// This partition is being flushed, we need to sync with global to make sure we have an up-to-date
			// partition map which will contain the new partition id
			while (true) {
				idx_t new_found_partition_idx;
				{
					unique_lock<mutex> lck_gstate(global_state->lock);

					new_found_partition_idx = global_state->partition_info.find(key)->second;
				}

				if (new_found_partition_idx != found_partition_idx) {


				} else {
					// TODO: how to efficiently wait for this?
					// - exponential sleeps?
				}
			}

		} else if (res == PartitionVersionStats::RegisterWriteResult::SHOULD_FLUSH){
			// This is crucial to do asap. Other threads will need to block until we have remapped
			RemapPartition(key, state);

			// With the new partition created, we will enter this waiting mode where we wait for other threads to finish
			// writing all their tuples to this partition
			FlushPartition(key, original_idx, 1);

		} else {
			// the RegisterWrite succeeded, we are cleared for writing this partition!
            return current_partition_idx;
		}
	}
}

void HivePartitionedColumnData::ComputePartitionIndices(PartitionedColumnDataAppendState &state, DataChunk &input) {
	Vector hashes(LogicalType::HASH, input.size());
	input.Hash(group_by_columns, hashes);
	hashes.Flatten(input.size());

	map<idx_t, idx_t> partition_counts;

	for (idx_t i = 0; i < input.size(); i++) {
		HivePartitionKey key;
		key.hash = FlatVector::GetData<hash_t>(hashes)[i];
		for (auto &col : group_by_columns) {
			key.values.emplace_back(input.GetValue(col, i));
		}

		auto lookup = local_partition_map.find(key);
		const auto partition_indices = FlatVector::GetData<idx_t>(state.partition_indices);
		if (lookup == local_partition_map.end()) {
			idx_t new_partition_id = RegisterNewPartition(key, state);
			partition_indices[i] = new_partition_id;
		} else {
			auto found_partition_idx = lookup->second;
			auto actual_idx = found_partition_idx;

			if (global_state && global_state->streaming_mode) {
				actual_idx = global_state->RegisterWrite(key, found_partition_idx);
			}

			partition_indices[i] = actual_idx;
		}
	}
}

std::map<idx_t, const HivePartitionKey *> HivePartitionedColumnData::GetReverseMap() {
	std::map<idx_t, const HivePartitionKey *> ret;
	for (const auto &pair : local_partition_map) {
		ret[pair.second] = &(pair.first);
	}
	return ret;
}

void HivePartitionedColumnData::GrowAllocators() {
	unique_lock<mutex> lck_gstate(allocators->lock);

	idx_t current_allocator_size = allocators->allocators.size();
	idx_t required_allocators = local_partition_map.size();

	allocators->allocators.reserve(current_allocator_size);
	for (idx_t i = current_allocator_size; i < required_allocators; i++) {
		CreateAllocator();
	}

	D_ASSERT(allocators->allocators.size() == local_partition_map.size());
}

void HivePartitionedColumnData::GrowAppendState(PartitionedColumnDataAppendState &state) {
	idx_t current_append_state_size = state.partition_append_states.size();
	idx_t required_append_state_size = local_partition_map.size();

	for (idx_t i = current_append_state_size; i < required_append_state_size; i++) {
		state.partition_append_states.emplace_back(make_unique<ColumnDataAppendState>());
		state.partition_buffers.emplace_back(CreatePartitionBuffer());
	}
}

void HivePartitionedColumnData::GrowPartitions(PartitionedColumnDataAppendState &state) {
	idx_t current_partitions = partitions.size();
	idx_t required_partitions = local_partition_map.size();

	D_ASSERT(allocators->allocators.size() == required_partitions);

	for (idx_t i = current_partitions; i < required_partitions; i++) {
		partitions.emplace_back(CreatePartitionCollection(i));
		partitions[i]->InitializeAppend(*state.partition_append_states[i]);
	}
	D_ASSERT(partitions.size() == local_partition_map.size());
}

// TODO requires lock, enforce through lock param, theres some other place this is done with the client context i think
void HivePartitionedColumnData::SynchronizeLocalMap() {
	// Synchronise global map into local, may contain changes from other threads too
	for (auto it = global_state->partitions.begin() + local_partition_map.size(); it < global_state->partitions.end();
	     it++) {
		local_partition_map[(*it)->first] = (*it)->second;
	}

	// Synchronise version vector
	for (auto it = global_state->partition_info.begin() + local_partition_info.size(); it < global_state->partition_info.end();
	     it++) {
		local_partition_info.push_back(*it);
	}

	// Apply all partition idx updates
	for (; applied_partition_update_idx < global_state->updates.size(); applied_partition_update_idx++) {
		auto update = global_state->updates[applied_partition_update_idx];
        local_partition_map[update.first] = update.second;
	}
}

idx_t HivePartitionedColumnData::RegisterNewPartition(HivePartitionKey key, PartitionedColumnDataAppendState &state) {
	if (global_state) {
		idx_t partition_id;

		// Synchronize Global state with our local state with the newly discovered partition
		{
			unique_lock<mutex> lck_gstate(global_state->lock);

			auto new_idx = global_state->partition_info.size(); // careful, partition_info size used as partition count!
			// Insert into global map, or return partition if already present
			auto res =
			    global_state->partition_map.emplace(std::make_pair(std::move(key), new_idx));
			// Create partition stats for the new partition
			global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>());
			auto it = res.first;
			partition_id = it->second;

			// Add iterator to vector to allow incrementally updating local states from global state
			global_state->partitions.emplace_back(it);
			SynchronizeLocalMap();
		}

		// After synchronizing with the global state, we need to grow the shared allocators to support
		// the number of partitions, which guarantees that there's always enough allocators available to each thread
		// Note: this is not racy, because SynchronizeLocalMap is always called with the global lock held.
		GrowAllocators();

		// Grow local partition data
		GrowAppendState(state);
		GrowPartitions(state);

		return partition_id;
	} else {
		return local_partition_map.emplace(std::make_pair(std::move(key), local_partition_map.size())).first->second;
	}
}

} // namespace duckdb
