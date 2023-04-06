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
	group_by_columns = other.group_by_columns;
	global_state = other.global_state;

	if (other.global_state) {
		unique_lock<mutex> lck(global_state->lock);
		global_state->total_writers++;

		// TODO: Aren't we in an inconsistent state if we call this without Grow after?
		SynchronizeLocalMap();
	}
}

void HivePartitionedColumnData::AssignNewPhysicalPartition(idx_t logical_partition_index, PartitionedColumnDataAppendState& state) {
	{
		unique_lock<mutex> lck_gstate(global_state->lock);

		auto new_idx = global_state->partition_info.size(); // careful, partition_info size used as partition count!
		global_state->version_map_updates.push_back({logical_partition_index, new_idx});
		global_state->version_map[logical_partition_index] = new_idx;

		// Create partition stats for the new partition
		auto limit = global_state->manager->GetPartitionTupleLimit();
		global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>(logical_partition_index, limit));

		// TODO: we could consider first releasing and growing the allocators before doing this so other threads are
		//       not blocked as long
		SynchronizeLocalMap();
	}

	Grow(state);
}

void HivePartitionedColumnData::FlushPartition(idx_t logical_partition_index, idx_t physical_partition_index, idx_t count) {
	auto& partition_info = local_partition_info[physical_partition_index];

	// Busy wait until all threads have finished writing to this physical partition, this guarantees we can flush
	// the physical partition from other HivePartitionedColumnData without needing locks for writing
	while (partition_info->started > partition_info->written + count) {
	}

	// TODO: is it a problem if a hpcd is registered after this point? I dont think so because it cant write to the physical
	//       partition anyway right?
	vector<HivePartitionedColumnData*> others;
	{
		unique_lock<mutex> lck(global_state->lock);
		for (auto& hpcd : global_state->manager->column_data) {
			others.push_back(hpcd.get());
		}
	}

	unique_ptr<ColumnDataCollection> combined;
	for (idx_t i = 0; i < others.size(); i++) {
		unique_ptr<ColumnDataCollection> current_cdc;
		{
			lock_guard<mutex> guard(others[i]->lock);
			if (physical_partition_index >= others[i]->partitions.size()) {
				continue;
			}
			current_cdc = std::move(others[i]->partitions[physical_partition_index]);
		}
		D_ASSERT(current_cdc);

		if (!combined) {
			combined = std::move(current_cdc);
		} else {
			combined->Combine(*current_cdc);
		}
	}
	D_ASSERT(combined);

	if (!flush_callback) {
		throw InternalException("Flush called on HivePartitionedColumnData without flush callback");
	}

	// TODO improve over linear search here?
	for (const auto& map_entry : local_partition_map) {
		if (map_entry.second == logical_partition_index) {
			flush_callback(map_entry.first, physical_partition_index, std::move(combined));
		}
	}

	// Free the shared allocator for this partition
	{
		unique_lock<mutex> lck_gstate(allocators->lock);
		allocators->allocators[physical_partition_index] = nullptr;
	}
}

// Ensures all data is flushed
void HivePartitionedColumnData::Finalize(PartitionedColumnDataAppendState& state) {
	// First we need to ensure our caches are flushed
	FlushAppendState(state);

	global_state->finished_writers++;

	// Busy wait for all writers to finish TODO: GOOD ENOUGH?
	while(global_state->total_writers != global_state->finished_writers) {
	}

	// TODO: This should be a method?
	{
		unique_lock<mutex> lck_gstate(global_state->lock);
		SynchronizeLocalMap();
	}
	GrowAllocators();
	GrowAppendState(state);
	GrowPartitions(state);

	// Go over each partition and try to claim it for flushing; either we flush it, or another thread is already on it
	for (idx_t logical_partition_idx = 0; logical_partition_idx < local_version_map.size(); logical_partition_idx++) {
		idx_t physical_partition_idx = local_version_map[logical_partition_idx];
		auto& current_physical_partition_info = local_partition_info[physical_partition_idx];
		auto res = current_physical_partition_info->RegisterFinalize();

		if (res == PartitionVersionStats::RegisterWriteResult::IS_FLUSHING) {
			continue;
		} else if (res == PartitionVersionStats::RegisterWriteResult::SHOULD_FLUSH) {
			auto limit = global_state->manager->GetPartitionTupleLimit();
			FlushPartition(logical_partition_idx, physical_partition_idx, limit);
		} else {
			throw InternalException("Invalid RegisterWriteResult returned while flushing");
		}
	}
}

idx_t HivePartitionedColumnData::RegisterWrite(PartitionedColumnDataAppendState& state, idx_t logical_partition_index, idx_t count) {
	D_ASSERT(logical_partition_index < local_version_map.size());
	auto current_physical_partition_idx = local_version_map[logical_partition_index];

	while (true) {
		D_ASSERT(current_physical_partition_idx < local_partition_info.size());
		auto& current_physical_partition_info = local_partition_info[current_physical_partition_idx];

		D_ASSERT(current_physical_partition_info);

		//! Try to register a write to this physical partition
		auto res = current_physical_partition_info->RegisterWrite(count);

		if (res == PartitionVersionStats::RegisterWriteResult::IS_FLUSHING) {
			// This partition is being flushed, we need to sync with global to make sure we have an up-to-date
			// partition map which will contain the new partition id
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
			// first thing to do after the SHOULD_FLUSH result is to ensure a new partition is made available as other
			// threads that want to append to this logical partition need to wait for this.
			AssignNewPhysicalPartition(logical_partition_index, state);

			// TODO: This access to the chunk that sent us over the edge so we can "top off" the partition to exactly the limit
			FlushPartition(logical_partition_index, current_physical_partition_idx, count);

			// TODO: it appears that after this step somehow the thread local version map is not yet up to date.

		} else if (res == PartitionVersionStats::RegisterWriteResult::SUCCESS) {
			// No conflicts, write has been registered
			return current_physical_partition_idx;
		} else {
			throw NotImplementedException("Unknown result returned from RegisterWrite in HivePartitionedColumnData");
		}

//		Printer::Print("\nEnd of Register loop");
	}
}

void HivePartitionedColumnData::FinishWrite(idx_t logical_index, idx_t physical_index, idx_t count) {
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
			partition_indices[i] = new_partition_id;
		} else {
			partition_indices[i] = lookup->second;
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

	allocators->allocators.reserve(current_allocator_size);
	for (idx_t i = current_allocator_size; i < required_allocators; i++) {
		CreateAllocator();
	}

	D_ASSERT(allocators->allocators.size() == local_partition_info.size());
}

void HivePartitionedColumnData::GrowAppendState(PartitionedColumnDataAppendState &state) {
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

// TODO: ensure this isn't called with other lock that could result in deadlock
void HivePartitionedColumnData::GrowPartitions(PartitionedColumnDataAppendState &state) {
	// We need to lock here, because other threads that want to flush may try to attempt to touch our partitions to flush em
	lock_guard<mutex> guard(lock);
	idx_t current_physical_partitions = partitions.size();
	idx_t required_physical_partitions = local_partition_info.size();

	D_ASSERT(allocators->allocators.size() >= required_physical_partitions);
	D_ASSERT(state.partition_append_states.size() >= required_physical_partitions);

	// TODO: only initialize the partitions we actually need
	lock_guard<mutex> alloc_guard(allocators->lock); // need to lock allocators here, TODO: can we improve on holding 2 locks?
	for (idx_t i = current_physical_partitions; i < required_physical_partitions; i++) {
		if (allocators->allocators[i]){
			partitions.emplace_back(CreatePartitionCollection(i));
			partitions[i]->InitializeAppend(*state.partition_append_states[i]);
		} else {
			// This partition will never be touched since it's already full
			partitions.emplace_back(nullptr);
		}
	}
	D_ASSERT(partitions.size() == local_partition_info.size());
}

// TODO requires lock, enforce through lock param, theres some other place this is done with the client context i think
void HivePartitionedColumnData::SynchronizeLocalMap() {
	local_partition_map = global_state->partition_map;
	local_version_map = global_state->version_map;
	local_partition_info = global_state->partition_info;

	return;

	// TODO: after preliminary testing, we need to figure out is this actually need speeding up, there's some potentially
	// high overhead code above with shared_ptr creation of O(t*p^2) with threads as t, partitions as p
	// however it may also be fine as other bottlenecks kick in first for high partition counts

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

				auto limit = global_state->manager->GetPartitionTupleLimit();
				global_state->partition_info.emplace_back(make_shared<PartitionVersionStats>(new_logical_idx,limit));

				partition_id = new_logical_idx;
			} else {
				partition_id = lookup->second;
			}

			SynchronizeLocalMap();
		}
		Grow(state);

		return partition_id;
	} else {
		// TODO: non-shared is not working
		return local_partition_map.emplace(std::make_pair(std::move(key), local_partition_map.size())).first->second;
	}
}

} // namespace duckdb
