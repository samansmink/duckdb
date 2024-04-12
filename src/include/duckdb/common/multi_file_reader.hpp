//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/multi_file_reader.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/enums/file_glob_options.hpp"
#include "duckdb/common/multi_file_reader_options.hpp"
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/union_by_name.hpp"

namespace duckdb {
class TableFunction;
class TableFunctionSet;
class TableFilterSet;
class LogicalGet;
class Expression;
class ClientContext;
class DataChunk;

struct HivePartitioningIndex {
	HivePartitioningIndex(string value, idx_t index);

	string value;
	idx_t index;

	DUCKDB_API void Serialize(Serializer &serializer) const;
	DUCKDB_API static HivePartitioningIndex Deserialize(Deserializer &deserializer);
};

//! This is used to pass custom data through the bind process of a table function
struct CustomMultiFileReaderBindData {
    virtual ~CustomMultiFileReaderBindData();
    // To be overridden
    // TODO how to serialize/deserialize? can we just rebind?
};

//! The bind data for the multi-file reader, obtained through MultiFileReader::BindReader
struct MultiFileReaderBindData {
	//! The index of the filename column (if any)
	idx_t filename_idx = DConstants::INVALID_INDEX;
	//! The set of hive partitioning indexes (if any)
	vector<HivePartitioningIndex> hive_partitioning_indexes;
	//! The index of the file_row_number column (if any)
	idx_t file_row_number_idx = DConstants::INVALID_INDEX;

    //! Overridable data for custom multifilereader implementations
    unique_ptr<CustomMultiFileReaderBindData> custom_data;

	DUCKDB_API void Serialize(Serializer &serializer) const;
	DUCKDB_API static MultiFileReaderBindData Deserialize(Deserializer &deserializer);
};

struct MultiFileFilterEntry {
	idx_t index = DConstants::INVALID_INDEX;
	bool is_constant = false;
};

struct MultiFileConstantEntry {
	MultiFileConstantEntry(idx_t column_id, Value value_p) : column_id(column_id), value(std::move(value_p)) {
	}

	//! The column id to apply the constant value to
	idx_t column_id;
	//! The constant value
	Value value;
};

//! MultiFileReaderData is the scan-related data of a single file to be read as part of a multi-file read
struct MultiFileReaderData {
	//! The column ids to read from the file
	vector<idx_t> column_ids;
	//! The mapping of column id -> result column id
	//! The result chunk will be filled as follows: chunk.data[column_mapping[i]] = ReadColumn(column_ids[i]);
	vector<idx_t> column_mapping;
	//! Whether or not there are no columns to read. This can happen when a file only consists of constants
	bool empty_columns = false;
	//! Filters can point to either (1) local columns in the file, or (2) constant values in the `constant_map`
	//! This map specifies where the to-be-filtered value can be found
	vector<MultiFileFilterEntry> filter_map;
	//! The set of table filters
	optional_ptr<TableFilterSet> filters;
	//! The constants that should be applied at the various positions
	vector<MultiFileConstantEntry> constant_map;
	//! Map of column_id -> cast, used when reading multiple files when files have diverging types
	//! for the same column
	unordered_map<column_t, LogicalType> cast_map;
};

//! Base class for a multi-file list that can be lazily generated
struct MultiFileList {
	virtual ~MultiFileList();
	//! Get the file at index i
	//! TODO: should I refactor the interface to reflect the fact that you should sequentially fetch them?
	virtual string GetFile(idx_t i) = 0;
	//! Get the whole list (Warning: this potentially returns more files that necessary if called before ComplexFilterPushdown)
	virtual vector<string> GetRawList();
	//! (optional) Push down filters into the MultiFileList; sometimes the filters can be used to skip files completely
	virtual bool ComplexFilterPushdown(ClientContext &context, const MultiFileReaderOptions &options, LogicalGet &get,
	                                             vector<unique_ptr<Expression>> &filters);
};

//! Simplest implementation of a MultiFilelist with, you guessed it, a list of files
struct SimpleMultiFileList : public MultiFileList {
	SimpleMultiFileList(vector<string> files);
	//! TODO: remove as many of the GetRawList as possible
	vector<string> GetRawList() override;
	string GetFile(idx_t i) override;
	bool ComplexFilterPushdown(ClientContext &context, const MultiFileReaderOptions &options, LogicalGet &get,
	                                   vector<unique_ptr<Expression>> &filters) override;
protected:
	vector<string> files;
};

// TODO: This API can be made simpler probably; its verbosity stems from the fact that this used to be all static.
//       perhaps we can make all state related to the MultiFileReader just live in the MultiFileReader? That way it has access to
//       everything and we solve the ugly dual ComplexFilterPushdown on the MultiFileList/MultiFileReader and the passing around
//       of MultiFileReaderData
struct MultiFileReader {
public:
    unique_ptr<MultiFileList> files;
    MultiFileReaderOptions options;

public:
    virtual ~MultiFileReader();

    //! Initialize the MultiFileReader; the `input` variable contains the (list of) files (or globs or both) to be read.
    DUCKDB_API virtual void InitializeFiles(ClientContext &context, const Value &input, const string &parent_function, FileGlobOptions glob_options);

	//! Add the parameters for multi-file readers (e.g. union_by_name, filename) to a table function
	DUCKDB_API virtual void AddParameters(TableFunction &table_function);
	//! Parse the named parameters of a multi-file reader
	DUCKDB_API virtual bool ParseOption(const string &key, const Value &val, ClientContext &context);
	//! Perform complex filter pushdown into the multi-file reader, potentially filtering out files that should be read
	//! If "true" the first file has been eliminated
	DUCKDB_API virtual bool ComplexFilterPushdown(ClientContext &context, LogicalGet &get, vector<unique_ptr<Expression>> &filters);
    //! Tries to use the MultiFileReader for binding. This method can be overridden by custom MultiFileReaders
    // TODO: is this quirky?
    DUCKDB_API virtual bool Bind(vector<LogicalType> &return_types, vector<string> &names, MultiFileReaderBindData &bind_data);
	//! Bind the options of the multi-file reader, potentially emitting any extra columns that are required
	DUCKDB_API virtual void BindOptions(vector<LogicalType> &return_types, vector<string> &names, MultiFileReaderBindData& bind_data);
	//! Finalize the bind phase of the multi-file reader after we know (1) the required (output) columns, and (2) the
	//! pushed down table filters
	DUCKDB_API virtual void FinalizeBind(const MultiFileReaderBindData &multi_file_bind_data,
                                         const string &filename, const vector<string> &local_names,
                                         const vector<LogicalType> &global_types, const vector<string> &global_names,
                                         const vector<column_t> &global_column_ids,
                                         MultiFileReaderData &reader_data, ClientContext &context);
	//! Create all required mappings from the global types/names to the file-local types/names
	DUCKDB_API virtual void CreateMapping(const string &file_name, const vector<LogicalType> &local_types,
	                                     const vector<string> &local_names, const vector<LogicalType> &global_types,
	                                     const vector<string> &global_names, const vector<column_t> &global_column_ids,
	                                     optional_ptr<TableFilterSet> filters, MultiFileReaderData &reader_data,
	                                     const string &initial_file);
	//! Populated the filter_map
	DUCKDB_API virtual void CreateFilterMap(const vector<LogicalType> &global_types,
	                                       optional_ptr<TableFilterSet> filters, MultiFileReaderData &reader_data);
	//! Finalize the reading of a chunk - applying any constants that are required
	DUCKDB_API virtual void FinalizeChunk(ClientContext &context, const MultiFileReaderBindData &bind_data,
	                                     const MultiFileReaderData &reader_data, DataChunk &chunk, const string &filename);

	//! Can remain static?

	//! Creates a table function set from a single reader function (including e.g. list parameters, etc)
	DUCKDB_API static TableFunctionSet CreateFunctionSet(TableFunction table_function);

	template <class READER_CLASS, class RESULT_CLASS, class OPTIONS_CLASS>
	static MultiFileReaderBindData BindUnionReader(ClientContext &context, MultiFileReader &multi_file_reader, vector<LogicalType> &return_types,
	                                               vector<string> &names, vector<string> &files, RESULT_CLASS &result,
	                                               OPTIONS_CLASS &options) {
		D_ASSERT(options.file_options.union_by_name);
		vector<string> union_col_names;
		vector<LogicalType> union_col_types;
		// obtain the set of union column names + types by unifying the types of all of the files
		// note that this requires opening readers for each file and reading the metadata of each file
		auto union_readers =
		    UnionByName::UnionCols<READER_CLASS>(context, files, union_col_types, union_col_names, options);

		std::move(union_readers.begin(), union_readers.end(), std::back_inserter(result.union_readers));
		// perform the binding on the obtained set of names + types
		SimpleMultiFileList simple_multi_file_list(files); // TODO: this is a bit wonky now
        MultiFileReaderBindData bind_data;
		multi_file_reader.BindOptions(union_col_types, union_col_names, bind_data);
		names = union_col_names;
		return_types = union_col_types;
		result.Initialize(result.union_readers[0]);
		D_ASSERT(names.size() == return_types.size());
		return bind_data;
	}

	template <class READER_CLASS, class RESULT_CLASS>
	static MultiFileReaderBindData BindReader(ClientContext &context, MultiFileReader &multi_file_reader, vector<LogicalType> &return_types,
	                                          vector<string> &names, RESULT_CLASS &result) {
		if (multi_file_reader.options.union_by_name) {
			//! Union by name requires reading all metadata (TODO: does it though?)
			vector<string> complete_file_list = multi_file_reader.files->GetRawList();
			return BindUnionReader<READER_CLASS>(context, multi_file_reader, return_types, names, complete_file_list, result);
		} else {
			// Default behaviour: get the 1st file and use its schema for scanning all files
			shared_ptr<READER_CLASS> reader;
			reader = make_shared<READER_CLASS>(context, multi_file_reader.files->GetFile(0));
			return_types = reader->return_types;
			names = reader->names;
			result.Initialize(std::move(reader));
            MultiFileReaderBindData bind_data;
			multi_file_reader.BindOptions(return_types, names, bind_data);
            return bind_data;
		}
	}

	// TODO this parameter list is insanely ugly now
	template <class READER_CLASS>
	static void InitializeReader(MultiFileReader &multi_file_reader, READER_CLASS &reader,
	                             const MultiFileReaderBindData &bind_data, const vector<LogicalType> &global_types,
	                             const vector<string> &global_names, const vector<column_t> &global_column_ids,
	                             optional_ptr<TableFilterSet> table_filters, const string &initial_file,
	                             ClientContext &context) {
		multi_file_reader.FinalizeBind(bind_data, reader.GetFileName(), reader.GetNames(), global_types, global_names,
		             global_column_ids, reader.reader_data, context);
		multi_file_reader.CreateMapping(reader.GetFileName(), reader.GetTypes(), reader.GetNames(), global_types, global_names,
		              global_column_ids, table_filters, reader.reader_data, initial_file);
		reader.reader_data.filters = table_filters;
	}

	template <class BIND_DATA>
	static void PruneReaders(BIND_DATA &data, vector<string> &files) {
		unordered_set<string> file_set;
		for (auto &file : files) {
			file_set.insert(file);
		}

		if (data.initial_reader) {
			// check if the initial reader should still be read
			auto entry = file_set.find(data.initial_reader->GetFileName());
			if (entry == file_set.end()) {
				data.initial_reader.reset();
			}
		}
		for (idx_t r = 0; r < data.union_readers.size(); r++) {
			if (!data.union_readers[r]) {
				data.union_readers.erase(data.union_readers.begin() + r);
				r--;
				continue;
			}
			// check if the union reader should still be read or not
			auto entry = file_set.find(data.union_readers[r]->GetFileName());
			if (entry == file_set.end()) {
				data.union_readers.erase(data.union_readers.begin() + r);
				r--;
				continue;
			}
		}
	}

protected:
	virtual void CreateNameMapping(const string &file_name, const vector<LogicalType> &local_types,
	                              const vector<string> &local_names, const vector<LogicalType> &global_types,
	                              const vector<string> &global_names, const vector<column_t> &global_column_ids,
	                              MultiFileReaderData &reader_data, const string &initial_file);
};

} // namespace duckdb
