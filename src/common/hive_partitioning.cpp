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
		// TODO add sanity check here to ensure we cannot add construct more of these after we've started writing
		// this would cause issues when handling the final flush (and possibly elsewhere too?)
		global_state = other.global_state;
		unique_lock<mutex> lck(global_state->lock);
		global_state->data_collections.push_back(this);
		global_state->total_writers++;
		SynchronizeLocalMap();
	}
}

void HivePartitionedColumnData::FlushPartition(idx_t logical_partition_index, idx_t physical_partition_index, idx_t count, PartitionedColumnDataAppendState* state) {
//	Printer::Print("\nFlushing partition (" + to_string(logical_partition_index) + ", " + to_string(physical_partition_index) + ")");

	// TODO: make explicit that we can have a flush that refreshes first or a flush that just flushes
	// Also: the rest of the function is probably also partially unnecessary? we should not need to wait in this case
	if (state) {
		{
			unique_lock<mutex> lck_gstate(global_state->lock);

			auto new_idx = global_state->partition_info.size(); // careful, partition_info size used as partition count!
			global_state->version_map_updates.push_back({logical_partition_index, new_idx});
			global_state->version_map[logical_partition_index] = new_idx;

			Printer::Print("Made new partition: " + to_string(new_idx));

			// Create partition stats for the new partition
			global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>(logical_partition_index));

			// TODO: we could consider first releasing and growing the allocators before doing this so other threads are
			//       not blocked as long
			SynchronizeLocalMap();
		}

		// Grow stuff
		GrowAllocators();
		GrowAppendState(*state);
		GrowPartitions(*state);
	} else {
		Printer::Print("BOOPBYOOOP");
	}

	//! - busy wait for other threads to finish writing to the old partition (wait for PartitionVersionStats.started = PartitionVersionStats.written)
	//! - merge columndatacollections from all threads, call flush_callback
	//! - free shared allocator for partition

	auto& partition_info = local_partition_info[physical_partition_index];

	//Printer::Print("\nReady for flushing!");
	//Printer::Print("  > Busy waiting for threads to finish with physical partition " + to_string(physical_partition_index));

	// busy wait for other threads to finish writing to this partition
	// TODO: we need to account for the tuples registered to our thread here!
	while (partition_info->started < partition_info->written) {
	}
	//Printer::Print("  > Done busy waiting on " + to_string(physical_partition_index));
	//Printer::Print("  > Merging " + to_string(global_state->data_collections.size()) + " partitions");
	// Merge partitions from all threads
	if (!state) {
		Printer::Print("DOIN " + to_string(physical_partition_index));
	}
	auto& combined = global_state->data_collections[0]->partitions[physical_partition_index];

	if (!combined) {
		Printer::Print("BEFO");
		throw InternalException("WHY");
	}
	for (idx_t i = 1; i < global_state->data_collections.size(); i++) {
		Printer::Print("Flushing partition " + to_string(physical_partition_index));
		Printer::Flush(OutputStream::STREAM_STDERR);

		auto& to_combine = global_state->data_collections[i]->partitions[physical_partition_index];
		combined->Combine(*to_combine);
		to_combine = nullptr; // TODO: this is reset now for dev/debug purposes, we may want to keep it since its empty anyway and we could reuse it
	}

	if (!flush_callback) {
		throw InternalException("Flush called on HivePartitionedColumnData without flush callback");
	}

	if (!combined) {
		throw InternalException("No data found!");
	}

	// TODO improve over linear search here
	//
	//Printer::Print("  > Searching for key");
	for (const auto& map_entry : local_partition_map) {
		if (map_entry.second == logical_partition_index) {
			//Printer::Print("  > key found: " + map_entry.first.values[0].ToString());
			flush_callback(map_entry.first, physical_partition_index, std::move(combined));
		}
	}

	// Now free the memory for this partition
	{
		unique_lock<mutex> lck_gstate(allocators->lock);
		allocators->allocators[physical_partition_index] = nullptr;
	}
}

void HivePartitionedColumnData::Finalize(PartitionedColumnDataAppendState& state) {
	//Printer::Print("\nFinalizing");
	// First we need to ensure our caches are flushed
	FlushAppendState(state);

	global_state->finished_writers++;
	//Printer::Print("  > Waiting for others to also finish");

	// Busy wait for writers to finish
	while(global_state->total_writers != global_state->finished_writers) {
	}

	//Printer::Print("  > Every thread is finished!");
	// Ensure we have an up-to-date view on the global state
	{
		unique_lock<mutex> lck_gstate(global_state->lock);
		SynchronizeLocalMap();
	}
	GrowAllocators();
	GrowAppendState(state);
	GrowPartitions(state);

	//Printer::Print("\nStarting flush cycle");
	for (idx_t logical_partition_idx = 0; logical_partition_idx < local_version_map.size(); logical_partition_idx++) {
		idx_t physical_partition_idx = local_version_map[logical_partition_idx];
		auto& current_physical_partition_info = local_partition_info[physical_partition_idx];
		auto res = current_physical_partition_info->RegisterFinalize();

		if (res == PartitionVersionStats::RegisterWriteResult::IS_FLUSHING) {
			// other thread is flushing this one;
			Printer::Print("Already being flushed: (" + to_string(logical_partition_idx) + ", " + to_string(physical_partition_idx) + ")");
			continue;
		} else if (res == PartitionVersionStats::RegisterWriteResult::SHOULD_FLUSH) {
			Printer::Print("We're flushing this one: (" + to_string(logical_partition_idx) + ", " + to_string(physical_partition_idx) + ")");
			FlushPartition(logical_partition_idx, physical_partition_idx, 0, nullptr);
		} else {
			//Printer::Print("DAFUQ?: (" + to_string(logical_partition_idx) + ", " + to_string(physical_partition_idx) + ")");
			// This should not happen: we just tried to flush NumericLimits<idx_t>::Maximum(), which should always result
			// in either us flushing the partition or another thread already flushing it.
			throw InternalException("Invalid RegisterWriteResult returned while flushing all");
		}
	}
}

idx_t HivePartitionedColumnData::RegisterWrite(PartitionedColumnDataAppendState& state, idx_t logical_partition_index, idx_t count) {
    //Printer::Print("\nRegistering write of size " + to_string(count) + " on logical index: " + to_string(logical_partition_index));
	auto current_physical_partition_idx = local_version_map[logical_partition_index];

	while (true) {
		if (current_physical_partition_idx >= local_partition_info.size()) {
			Printer::Print("Failed to read physical: " + to_string(current_physical_partition_idx));
			Printer::Print("available size = " + to_string(local_partition_info.size()));
			throw FatalException("BOOP");
		}

		auto& current_physical_partition_info = local_partition_info[current_physical_partition_idx];
		D_ASSERT(current_physical_partition_info);

		//! Try to register a write to this physical partition
		auto res = current_physical_partition_info->RegisterWrite(count);

		if (res == PartitionVersionStats::RegisterWriteResult::IS_FLUSHING) {
			//Printer::Print("Write of size " + to_string(count) + " on logical idx : " + to_string(logical_partition_index) + " for idx " + to_string(current_physical_partition_idx));
			//Printer::Print(" -> IS_FLUSHING!");

			// This partition is being flushed, we need to sync with global to make sure we have an up-to-date
			// partition map which will contain the new partition id
			//Printer::Print(" -> WAITING");
			while (true) {

				idx_t new_found_partition_idx;
				bool found_new = false;
				{
					unique_lock<mutex> lck_gstate(global_state->lock);
					new_found_partition_idx = global_state->version_map[logical_partition_index];

					if (new_found_partition_idx != current_physical_partition_idx) {
						found_new = true;
						current_physical_partition_idx = new_found_partition_idx;
						SynchronizeLocalMap();
					}
				}

				if (found_new) {
					GrowAllocators();
					GrowAppendState(state);
					GrowPartitions(state);
					break;
				} else {
					// Here we need to wait for the other thread to
					// TODO: we probably need some exponential backoff here? to prevent threads from blocking the actual
					//       thread that needs to allocate the new partition
				}
			}

		} else if (res == PartitionVersionStats::RegisterWriteResult::SHOULD_FLUSH){
			// This is crucial to do asap. Other threads will need to block until we have remapped
			//Printer::Print("Write of size " + to_string(count) + " on logical idx : " + to_string(logical_partition_index) + " for idx " + to_string(current_physical_partition_idx));
			//Printer::Print(" -> SHOULD_FLUSH!");

			// With the new partition created, we will enter this waiting mode where we wait for other threads to finish
			// writing all their tuples to this partition

			FlushPartition(logical_partition_index, current_physical_partition_idx, count, &state);

			// TODO: it appears that after this step somehow the thread local version map is not yet up to date.

		} else if (res == PartitionVersionStats::RegisterWriteResult::SUCCESS) {
			// No conflicts, write has been registered
			return current_physical_partition_idx;
		} else {
			throw NotImplementedException("Unknown result returned from RegisterWrite in HivePartitionedColumnData");
		}

		//Printer::Print("\nEnd of Register loop");
	}
}

void HivePartitionedColumnData::FinishWrite(idx_t logical_index, idx_t physical_index, idx_t count) {
	//Printer::Print("Finished write of size " + to_string(count) + " on logical index: " + to_string(logical_index) + " for physical index " + to_string(physical_index));
	local_partition_info[physical_index]->written += count;
}

void HivePartitionedColumnData::ComputePartitionIndices(PartitionedColumnDataAppendState &state, DataChunk &input) {
	Vector hashes(LogicalType::HASH, input.size());
	input.Hash(group_by_columns, hashes);
	hashes.Flatten(input.size());

	map<HivePartitionKey, idx_t> partition_counts;

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
//			//Printer::Print("Key: " + key.values[0].ToString() + " = " + to_string(new_partition_id) + " NEW");
			partition_indices[i] = new_partition_id;
		} else {
			partition_indices[i] = lookup->second;
//			//Printer::Print("Key: " + key.values[0].ToString() + " = " + to_string(lookup->second) + " OLD");
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

// TODO: can make this lock less with atomic of total count, to allow only locking when growing
void HivePartitionedColumnData::GrowAllocators() {
	unique_lock<mutex> lck_gstate(allocators->lock);

	idx_t current_allocator_size = allocators->allocators.size();
	idx_t required_allocators = local_partition_info.size();

//	//Printer::Print("  > Growing allocators from " + to_string(current_allocator_size) + " to " + to_string(required_allocators));

	allocators->allocators.reserve(current_allocator_size);
	for (idx_t i = current_allocator_size; i < required_allocators; i++) {
		CreateAllocator();
	}

	D_ASSERT(allocators->allocators.size() == local_partition_info.size());
}

void HivePartitionedColumnData::GrowAppendState(PartitionedColumnDataAppendState &state) {
//	Printer::Print("  > Growing append state from " + to_string(current_append_state_size) + " to " + to_string(required_append_state_size));
	idx_t current_append_state_size = state.partition_append_states.size();
	idx_t required_append_state_size = local_partition_info.size();
	for (idx_t i = current_append_state_size; i < required_append_state_size; i++) {
		state.partition_append_states.emplace_back(make_unique<ColumnDataAppendState>());
	}

	idx_t current_partition_buffers_size = state.partition_buffers.size();
	idx_t required_partition_buffers_size = local_partition_map.size();
	for (idx_t i = current_partition_buffers_size; i < required_partition_buffers_size; i++) {
		state.partition_buffers.emplace_back(CreatePartitionBuffer());
	}
}

// TODO: append states are per logical partition, not per physical, so we need the mapping here
void HivePartitionedColumnData::GrowPartitions(PartitionedColumnDataAppendState &state) {
	idx_t current_physical_partitions = partitions.size();
	idx_t required_physical_partitions = local_partition_info.size();
//	Printer::Print("  > Growing partitions from " + to_string(current_physical_partitions) + " to " + to_string(required_physical_partitions));

	D_ASSERT(allocators->allocators.size() == required_physical_partitions);

	for (idx_t i = current_physical_partitions; i < required_physical_partitions; i++) {
		partitions.emplace_back(CreatePartitionCollection(i));
		partitions[i]->InitializeAppend(*state.partition_append_states[i]);
	}
	D_ASSERT(partitions.size() == local_partition_info.size());
}

// TODO requires lock, enforce through lock param, theres some other place this is done with the client context i think
void HivePartitionedColumnData::SynchronizeLocalMap() {
	Printer::RawPrint(OutputStream::STREAM_STDERR, "\n");
	Printer::Print("SyncLocalmap");
	Printer::Print("  > local_partition_map_size " + to_string(local_partition_map.size()) + " to global size of " + to_string(global_state->partition_map.size()));
	local_partition_map = global_state->partition_map;
	Printer::Print("  > local_version_map_size " + to_string(local_version_map.size()) + " to global size of " + to_string(global_state->version_map.size()));
	local_version_map = global_state->version_map;
	Printer::Print("  > local_partition_info_size " + to_string(local_partition_info.size()) + " to global size of " + to_string(global_state->partition_info.size()));
	local_partition_info = global_state->partition_info;

	for (idx_t i = 0; i < local_version_map.size(); i++) {
		Printer::Print("  > " + to_string(i) + " = " + to_string(local_version_map[i]));
	}
	return;

	// TODO: make more efficient
//	// Synchronise global map into local, may contain changes from other threads too
//	for (auto it = global_state->partitions.begin() + local_partition_info.size(); it < global_state->partitions.end();
//	     it++) {
//		local_partition_map[(*it)->first] = (*it)->second;
//	}
//
//	// Synchronise version vector
//	for (auto it = global_state->partition_info.begin() + local_partition_info.size(); it < global_state->partition_info.end();
//	     it++) {
//		local_partition_info.push_back(*it);
//	}
//
//	// Update the local version map: note that we first resize then apply all updates. This means that when a partition
//	// is added, we require adding a partition update.
//	local_version_map.resize(local_partition_map.size());
//
//	// Apply all partition idx updates
//	for (; applied_partition_update_idx < global_state->version_map_updates.size(); applied_partition_update_idx++) {
//		auto update = global_state->version_map_updates[applied_partition_update_idx];
//		local_version_map[update.first] = update.second;
//	}
}

// TODO also register version
idx_t HivePartitionedColumnData::RegisterNewPartition(HivePartitionKey key, PartitionedColumnDataAppendState &state) {
//	Printer::Print("\nRegisterNewPartition " + key.values[0].ToString());
	if (global_state) {
		idx_t partition_id;

		// Synchronize Global state with our local state with the newly discovered partition
		{
			unique_lock<mutex> lck_gstate(global_state->lock);

			auto lookup = global_state->partition_map.find(key);

			if (lookup == global_state->partition_map.end()) {
				auto new_physical_idx = global_state->partition_info.size(); // careful, partition_info size used as partition count!
				auto new_logical_idx = global_state->version_map.size();

				// add the partition to the global partition map
				global_state->partition_map.emplace(std::make_pair(std::move(key), new_logical_idx));
				// add the physical idx to the version map
				global_state->version_map.push_back(new_physical_idx);
				// add partition info for this partition
				global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>(new_logical_idx));

				partition_id = new_logical_idx;
			} else {
				partition_id = lookup->second;
			}

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
		// TODO: non-shared is not working
		return local_partition_map.emplace(std::make_pair(std::move(key), local_partition_map.size())).first->second;
	}
}

} // namespace duckdb
