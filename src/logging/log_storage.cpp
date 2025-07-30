#include "duckdb/logging/log_storage.hpp"

#include "duckdb/common/csv_utils.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/function/table/read_csv.hpp"
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/main/database_file_opener.hpp"
#include "duckdb/logging/logging.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/tableref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/function/cast/vector_cast_helpers.hpp"
#include "duckdb/common/operator/string_cast.hpp"

#include <iostream>

namespace duckdb {

unique_ptr<LogStorageScanState> LogStorage::CreateScanEntriesState() const {
	throw NotImplementedException("Not implemented for this LogStorage: CreateScanEntriesState");
}
bool LogStorage::ScanEntries(LogStorageScanState &state, DataChunk &result) const {
	throw NotImplementedException("Not implemented for this LogStorage: ScanEntries");
}
void LogStorage::InitializeScanEntries(LogStorageScanState &state) const {
	throw NotImplementedException("Not implemented for this LogStorage: InitializeScanEntries");
}
unique_ptr<LogStorageScanState> LogStorage::CreateScanContextsState() const {
	throw NotImplementedException("Not implemented for this LogStorage: CreateScanContextsState");
}
bool LogStorage::ScanContexts(LogStorageScanState &state, DataChunk &result) const {
	throw NotImplementedException("Not implemented for this LogStorage: ScanContexts");
}
void LogStorage::InitializeScanContexts(LogStorageScanState &state) const {
	throw NotImplementedException("Not implemented for this LogStorage: InitializeScanContexts");
}
void LogStorage::Truncate() {
	throw NotImplementedException("Not implemented for this LogStorage: TruncateLogStorage");
}

void LogStorage::UpdateConfig(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	if (config.size() > 1) {
		throw InvalidInputException("LogStorage does not support passing configuration");
	}
}

unique_ptr<TableRef> LogStorage::BindReplaceEntries(ClientContext &context, TableFunctionBindInput &input) {
	return nullptr;
}

unique_ptr<TableRef> LogStorage::BindReplaceContexts(ClientContext &context, TableFunctionBindInput &input) {
	return nullptr;
}

CSVLogStorage::~CSVLogStorage() {
}

CSVLogStorage::CSVLogStorage(DatabaseInstance &db) : BufferingLogStorage(db) {
	ResetCastChunk();
}

void CSVLogStorage::ResetCastChunk() {
	log_entries_cast_chunk = make_uniq<DataChunk>();
	log_contexts_cast_chunk = make_uniq<DataChunk>();

	// Initialize the Cast chunks for casting everything to strings
	vector<LogicalType> types;
	types.resize(log_entries_buffer->ColumnCount(), LogicalType::VARCHAR);
	log_entries_cast_chunk->Initialize(Allocator::DefaultAllocator(), types);

	types.resize(log_contexts_buffer->ColumnCount(), LogicalType::VARCHAR);
	log_contexts_cast_chunk->Initialize(Allocator::DefaultAllocator(), types);
}

void CSVLogStorage::UpdateConfig(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	lock_guard<mutex> lck(lock);
	return UpdateConfigInternal(db, config);
}

// TODO: clean up
void CSVLogStorage::ExecuteCast() {
	log_entries_cast_chunk->Reset();
	log_contexts_cast_chunk->Reset();

	bool success = true;

	// TODO: tweak this?
	CastParameters cast_params;

	if (normalize_contexts) {
		// -- Cast Log Entries
		// context_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[0], log_entries_cast_chunk->data[0], log_entries_buffer->size(), cast_params);
		// timestamp: LogicalType::TIMESTAMP
		success &= VectorCastHelpers::StringCast<timestamp_t, duckdb::StringCast>(log_entries_buffer->data[1], log_entries_cast_chunk->data[1], log_entries_buffer->size(), cast_params);
		// log_type: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[2].Reference(log_entries_buffer->data[2]);
		// level: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[3].Reference(log_entries_buffer->data[3]);
		// message: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[4].Reference(log_entries_buffer->data[4]);

		log_entries_cast_chunk->SetCardinality(log_entries_buffer->size());

		// -- Cast Log Contexts
		// context_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_contexts_buffer->data[0], log_contexts_cast_chunk->data[0], log_contexts_buffer->size(), cast_params);
		// scope: LogicalType::VARCHAR (no cast)
		log_contexts_cast_chunk->data[1].Reference(log_contexts_buffer->data[1]);
		// connection_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_contexts_buffer->data[2], log_contexts_cast_chunk->data[2], log_contexts_buffer->size(), cast_params);
		// transaction_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_contexts_buffer->data[3], log_contexts_cast_chunk->data[3], log_contexts_buffer->size(), cast_params);
		// query_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_contexts_buffer->data[4], log_contexts_cast_chunk->data[4], log_contexts_buffer->size(), cast_params);
		// thread: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_contexts_buffer->data[5], log_contexts_cast_chunk->data[5], log_contexts_buffer->size(), cast_params);
		// scope is already string so doesn't need casting

		log_contexts_cast_chunk->SetCardinality(log_contexts_buffer->size());
	} else {
		// -- Cast Log Entries

		// context_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[0], log_entries_cast_chunk->data[0], log_entries_buffer->size(), cast_params);
		// scope: LogicalType::VARCHAR (no cast)
		log_entries_cast_chunk->data[1].Reference(log_entries_buffer->data[1]);
		// connection_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[2], log_entries_cast_chunk->data[2], log_entries_buffer->size(), cast_params);
		// transaction_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[3], log_entries_cast_chunk->data[3], log_entries_buffer->size(), cast_params);
		// query_id: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[4], log_entries_cast_chunk->data[4], log_entries_buffer->size(), cast_params);
		// thread: LogicalType::UBIGINT
		success &= VectorCastHelpers::StringCast<idx_t, duckdb::StringCast>(log_entries_buffer->data[5], log_entries_cast_chunk->data[5], log_entries_buffer->size(), cast_params);
		// timestamp: LogicalType::TIMESTAMP
		success &= VectorCastHelpers::StringCast<timestamp_t, duckdb::StringCast>(log_entries_buffer->data[6], log_entries_cast_chunk->data[6], log_entries_buffer->size(), cast_params);
		// log_type: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[7].Reference(log_entries_buffer->data[7]);
		// level: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[8].Reference(log_entries_buffer->data[8]);
		// message: LogicalType::VARCHAR  (no cast)
		log_entries_cast_chunk->data[9].Reference(log_entries_buffer->data[9]);

		log_entries_cast_chunk->SetCardinality(log_entries_buffer->size());
	}

	if (!success) {
		throw InvalidInputException("Failed to cast log entries");
	}

}

void CSVLogStorage::SetWriterConfigs(CSVWriter& writer, vector<string> column_names) {
	writer.options.dialect_options.state_machine_options.escape = '\"';
	writer.options.dialect_options.state_machine_options.quote = '\"';
	writer.options.dialect_options.state_machine_options.delimiter = CSVOption<string>("\t");
	writer.options.name_list = column_names;

	writer.options.force_quote = vector<bool>(column_names.size(), false);
}


void CSVLogStorage::FlushInternal() {
	// Execute the cast
	ExecuteCast();

	// Write the cast data to sCSV
	log_entries_writer->WriteChunk(*log_entries_cast_chunk, *log_entries_state);
	log_entries_buffer->Reset();

	log_contexts_writer->WriteChunk(*log_contexts_cast_chunk, *log_contexts_state);
	log_contexts_buffer->Reset();
}

void CSVLogStorage::UpdateConfigInternal(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	for (const auto &it : config) {
		if (StringUtil::Lower(it.first) == "buffer_size") {
			buffer_limit = it.second.GetValue<uint64_t>();
		} else {
			throw InvalidInputException("Unrecognized log storage config option: '%s'", it.first);
		}
	}
}

StdOutLogStorage::StdOutLogStorage(DatabaseInstance &db) : CSVLogStorage(db) {
	log_entries_stream = make_uniq<MemoryStream>();
	log_contexts_stream = make_uniq<MemoryStream>();
	log_entries_writer = make_uniq<CSVWriter>(*log_contexts_stream, GetEntriesColumnNames(true));
	log_contexts_writer = make_uniq<CSVWriter>(*log_contexts_stream, GetContextsColumnNames());
	log_entries_state = log_entries_writer->InitializeLocalWriteState(db);
	log_contexts_state = log_contexts_writer->InitializeLocalWriteState(db);

	SetWriterConfigs(*log_entries_writer, GetEntriesColumnNames(normalize_contexts));
	SetWriterConfigs(*log_contexts_writer, GetContextsColumnNames());
}

StdOutLogStorage::~StdOutLogStorage() {
}

void StdOutLogStorage::FlushInternal() {
	// Flush CSV buffer into stream
	CSVLogStorage::FlushInternal();

	// Write stream to stdout
	std::cout.write(const_char_ptr_cast(log_entries_stream->GetData()),
	                NumericCast<int64_t>(log_entries_stream->GetPosition()));
	std::cout.flush();
	log_entries_stream->Rewind();
}

static string GetDefaultPath(DatabaseInstance &db, const string &filename) {
	auto &fs = db.GetFileSystem();
	DatabaseFileOpener opener(db);
	auto default_path = FileSystem::GetHomeDirectory(opener);
	default_path = fs.JoinPath(default_path, ".duckdb");
	default_path = fs.JoinPath(default_path, "logs");
	default_path = fs.JoinPath(default_path, filename);
	return default_path;
}

string FileLogStorage::GetDefaultLogEntriesFilePath(DatabaseInstance &db) {
	return GetDefaultPath(db, "log_entries.csv");
}

string FileLogStorage::GetDefaultLogContextsFilePath(DatabaseInstance &db) {
	return GetDefaultPath(db, "log_contexts.csv");
}

FileLogStorage::FileLogStorage(DatabaseInstance &db_p) : CSVLogStorage(db_p), db(db_p) {
}

FileLogStorage::~FileLogStorage() {
}

void FileLogStorage::WriteLogEntriesHeader() {
	log_entries_writer->WriteHeader();
	log_entries_should_write_header = false;
}

void FileLogStorage::WriteLogContextsHeader() {
	log_contexts_writer->WriteHeader();
	log_contexts_should_write_header = false;
}

void FileLogStorage::InitializeLogContextsFile(DatabaseInstance &db, const string &path) {
	auto path_to_set = !path.empty() ? path : GetDefaultLogContextsFilePath(db);
	InitializeFile(db, path_to_set, log_contexts_should_write_header);

	// Refresh BufferedFileWriter
	auto &fs = db.GetFileSystem();
	FileCompressionType compression = FileCompressionType::UNCOMPRESSED;
	log_contexts_file_writer = make_uniq<BufferedFileWriter>(fs, path_to_set, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_APPEND | FileLockType::WRITE_LOCK | compression);
	log_contexts_writer = make_uniq<CSVWriter>(*log_contexts_file_writer, GetContextsColumnNames());
	log_contexts_state = log_contexts_writer->InitializeLocalWriteState(db);

	SetWriterConfigs(*log_contexts_writer, GetContextsColumnNames());
}

// TODO: clean up
void FileLogStorage::InitializeLogEntriesFile(DatabaseInstance &db, const string &path) {
	auto path_to_set = !path.empty() ? path : GetDefaultLogEntriesFilePath(db);
	InitializeFile(db, path_to_set, log_entries_should_write_header);

	auto &fs = db.GetFileSystem();
	FileCompressionType compression = FileCompressionType::UNCOMPRESSED;
	log_entries_file_writer = make_uniq<BufferedFileWriter>(fs, path_to_set, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_APPEND | FileLockType::WRITE_LOCK | compression);
	log_entries_writer = make_uniq<CSVWriter>(*log_entries_file_writer, GetEntriesColumnNames(true));
	log_entries_state = log_entries_writer->InitializeLocalWriteState(db);

	SetWriterConfigs(*log_entries_writer, GetEntriesColumnNames(normalize_contexts));
}

void FileLogStorage::InitializeFile(DatabaseInstance &db, const string &path, bool &should_write_header) {
	auto &fs = db.GetFileSystem();

	// Create parent directories if non existent
	auto pos = path.find_last_of(fs.PathSeparator(path));
	if (pos != path.npos) {
		fs.CreateDirectoriesRecursive(path.substr(0, pos));
	}

	unique_ptr<FileHandle> handle;
	if (!fs.FileExists(path)) {
		handle = fs.OpenFile(path,
		                     FileFlags::FILE_FLAGS_DISABLE_LOGGING | FileFlags::FILE_FLAGS_WRITE |
		                         FileFlags::FILE_FLAGS_FILE_CREATE_NEW,
		                     nullptr);
	} else {
		handle = fs.OpenFile(
		    path, FileFlags::FILE_FLAGS_DISABLE_LOGGING | FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_APPEND,
		    nullptr);
	}

	if (handle->GetFileSize() == 0) {
		should_write_header = true;
	}
}

void FileLogStorage::Truncate() {
	lock_guard<mutex> lck(lock);

	// TODO: this is stupid:
	// - don't flush, truncate

	log_entries_writer->Flush(*log_entries_state);
	log_entries_file_writer->Truncate(0);
	log_entries_writer->WriteHeader(); // TODO: is this correct?

	if (normalize_contexts) {
		log_contexts_writer->Flush(*log_contexts_state);
		log_contexts_file_writer->Truncate(0);
		log_contexts_writer->WriteHeader(); // TODO: is this correct?
	}

	BufferingLogStorage::ResetBuffers();
}

void FileLogStorage::FlushInternal() {
	ExecuteCast();

	// printf("Flushing log storage, the cast chunk contains:\n");
	// log_entries_buffer->Print();
	// log_entries_cast_chunk->Print();

	if (!initialized) {
		InitializeLogEntriesFile(db);
		if (normalize_contexts) {
			InitializeLogContextsFile(db);
		}
		initialized = true;
	}

	if (log_contexts_buffer->size() > 0) {
		// TODO: let CSV Writer handle?
		if (log_contexts_should_write_header) {
			WriteLogContextsHeader();
		}

		log_contexts_writer->WriteChunk(*log_contexts_cast_chunk, *log_contexts_state);
		log_contexts_writer->Flush(*log_contexts_state); // TODO: auto-flush on flushing storage?
		log_contexts_file_writer->Sync();
		log_contexts_buffer->Reset();
	}

	if (log_entries_buffer->size() > 0) {
		// TODO: let CSV Writer handle?
		if (log_entries_should_write_header) {
			WriteLogEntriesHeader();
		}

		log_entries_writer->WriteChunk(*log_entries_cast_chunk, *log_entries_state);
		log_entries_writer->Flush(*log_entries_state); // TODO: auto-flush on flushing storage?
		log_entries_file_writer->Sync();
		log_entries_buffer->Reset();
	}
}

void FileLogStorage::UpdateConfigInternal(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	auto config_copy = config;

	string contexts_path;
	string entries_path;

	bool old_normalize_contexts = normalize_contexts;

	vector<string> to_remove;
	for (const auto &it : config_copy) {
		if (StringUtil::Lower(it.first) == "path") {
			entries_path = it.second.ToString();
			to_remove.push_back(it.first);
			normalize_contexts = false;
		} else if (StringUtil::Lower(it.first) == "contexts_path") {
			contexts_path = it.second.ToString();
			to_remove.push_back(it.first);
			normalize_contexts = true;
		} else if (StringUtil::Lower(it.first) == "entries_path") {
			entries_path = it.second.ToString();
			to_remove.push_back(it.first);
			normalize_contexts = true;
		}
	}

	if (old_normalize_contexts != normalize_contexts) {
		ResetBufferChunk();
		ResetCastChunk();
	}

	if (!contexts_path.empty() || !entries_path.empty()) {
		FlushInternal();
	}
	if (!entries_path.empty()) {
		InitializeLogEntriesFile(db, entries_path);
	}
	if (!contexts_path.empty()) {
		InitializeLogContextsFile(db, contexts_path);
	}

	for (const auto &it : to_remove) {
		config_copy.erase(it);
	}

	CSVLogStorage::UpdateConfigInternal(db, config_copy);
}

unique_ptr<TableRef> FileLogStorage::BindReplaceInternal(ClientContext &context, TableFunctionBindInput &input,
                                                         const string &path, const string &select_clause) {
	string sub_query_string;

	string escaped_path = KeywordHelper::WriteOptionallyQuoted(path);
	sub_query_string = StringUtil::Format("%s FROM %s", select_clause, escaped_path);

	Parser parser(context.GetParserOptions());
	parser.ParseQuery(sub_query_string);
	auto select_stmt = unique_ptr_cast<SQLStatement, SelectStatement>(std::move(parser.statements[0]));

	return duckdb::make_uniq<SubqueryRef>(std::move(select_stmt));
}

unique_ptr<TableRef> FileLogStorage::BindReplaceEntries(ClientContext &context, TableFunctionBindInput &input) {
	lock_guard<mutex> lck(lock);
	FlushInternal();

	if (log_entries_file_writer) {
		return BindReplaceInternal(
		    context, input, log_entries_file_writer->path,
		    "SELECT context_id::UBIGINT as context_id, timestamp::TIMESTAMP as timestamp, log_type::VARCHAR as type, "
		    "level::VARCHAR as log_level, message::VARCHAR as message");
	}
	return nullptr;
}

unique_ptr<TableRef> FileLogStorage::BindReplaceContexts(ClientContext &context, TableFunctionBindInput &input) {
	lock_guard<mutex> lck(lock);
	FlushInternal();
	if (normalize_contexts) {
		D_ASSERT(log_contexts_file_writer);
		return BindReplaceInternal(context, input, log_contexts_file_writer->path,
		                           "SELECT context_id::UBIGINT as context_id, scope::VARCHAR as scope, "
		                           "connection_id::UBIGINT as connection_id, transaction_id::UBIGINT as "
		                           "transaction_id, query_id::UBIGINT as query_id, thread::UBIGINT as thread_id");
	}

	// When log contexts are denormalized in the csv files, we will be reading them horribly inefficiently by doing a
	// select DISTINCT on the log_entries_file_handle
	// TODO: fix? throw?
	return BindReplaceInternal(context, input, log_entries_file_writer->path,
	                           "SELECT DISTINCT context_id::UBIGINT as context_id, scope::VARCHAR as scope, "
	                           "connection_id::UBIGINT as connection_id, transaction_id::UBIGINT as transaction_id, "
	                           "query_id::UBIGINT as query_id, thread::UBIGINT as thread_id");
}

BufferingLogStorage::BufferingLogStorage(DatabaseInstance &db_p) {
	ResetBufferChunk();
}

void BufferingLogStorage::ResetBufferChunk() {
	max_buffer_size = STANDARD_VECTOR_SIZE; // TODO dedup
	log_entries_buffer = make_uniq<DataChunk>();
	log_contexts_buffer = make_uniq<DataChunk>();
	log_entries_buffer->Initialize(Allocator::DefaultAllocator(), GetEntriesSchema(normalize_contexts), STANDARD_VECTOR_SIZE);
	log_contexts_buffer->Initialize(Allocator::DefaultAllocator(), GetContextsSchema(), STANDARD_VECTOR_SIZE);
}

InMemoryLogStorageScanState::InMemoryLogStorageScanState() {
}
InMemoryLogStorageScanState::~InMemoryLogStorageScanState() {
}

InMemoryLogStorage::InMemoryLogStorage(DatabaseInstance &db_p)
    : BufferingLogStorage(db_p) {
	max_buffer_size = STANDARD_VECTOR_SIZE;
	log_entries = make_uniq<ColumnDataCollection>(db_p.GetBufferManager(), GetEntriesSchema(true));
	log_contexts = make_uniq<ColumnDataCollection>(db_p.GetBufferManager(), GetContextsSchema());
}

vector<LogicalType> BufferingLogStorage::GetEntriesSchema(bool normalize) {
	if (normalize) {
		return {
			LogicalType::UBIGINT,   // context_id
			LogicalType::TIMESTAMP, // timestamp
			LogicalType::VARCHAR,   // log_type TODO: const vector where possible?
			LogicalType::VARCHAR,   // level TODO: enumify
			LogicalType::VARCHAR,   // message
		};
	}

	return {
		LogicalType::UBIGINT,   // context_id
		LogicalType::VARCHAR,   // scope
		LogicalType::UBIGINT,   // connection_id
		LogicalType::UBIGINT,   // transaction_id
		LogicalType::UBIGINT,   // query_id
		LogicalType::UBIGINT,   // thread
		LogicalType::TIMESTAMP, // timestamp
		LogicalType::VARCHAR,   // log_type TODO: const vector where possible?
		LogicalType::VARCHAR,   // level TODO: enumify
		LogicalType::VARCHAR,   // message
	};
}

vector<LogicalType> BufferingLogStorage::GetContextsSchema() {
	return {
		LogicalType::UBIGINT, // context_id
		LogicalType::VARCHAR, // scope TODO: enumify
		LogicalType::UBIGINT, // connection_id
		LogicalType::UBIGINT, // transaction_id
		LogicalType::UBIGINT, // query_id
		LogicalType::UBIGINT, // thread
	};
}

vector<string> BufferingLogStorage::GetEntriesColumnNames(bool normalize) {
	if (normalize) {
		return {
			"context_id",
			"timestamp",
			"log_type",
			"level",
			"message"
		};
	}

	return {
		"context_id",
		"scope",
		"connection_id",
		"transaction_id",
		"query_id",
		"thread",
		"timestamp",
		"log_type",
		"level",
		"message",
	};
}

vector<string> BufferingLogStorage::GetContextsColumnNames() {
	return {
		"context_id",
		"scope",
		"connection_id",
		"transaction_id",
		"query_id",
		"thread",
	};
}

void InMemoryLogStorage::ResetBuffers() {
	log_entries->Reset();
	log_contexts->Reset();

	BufferingLogStorage::ResetBuffers();
}

InMemoryLogStorage::~InMemoryLogStorage() {
}

BufferingLogStorage::~BufferingLogStorage() {
}

static void WriteLoggingContextsToChunk(DataChunk &chunk, const RegisteredLoggingContext &context, idx_t &col) {

	auto size = chunk.size();

	auto context_id_data = FlatVector::GetData<idx_t>(chunk.data[col++]);
	context_id_data[size] = context.context_id;

	auto context_scope_data = FlatVector::GetData<string_t>(chunk.data[col]);
	context_scope_data[size] =
		StringVector::AddString(chunk.data[col++], EnumUtil::ToString(context.context.scope));

	if (context.context.connection_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(chunk.data[col++]);
		client_context_data[size] = context.context.connection_id.GetIndex();
	} else {
		FlatVector::Validity(chunk.data[col++]).SetInvalid(size);
	}
	if (context.context.transaction_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(chunk.data[col++]);
		client_context_data[size] = context.context.transaction_id.GetIndex();
	} else {
		FlatVector::Validity(chunk.data[col++]).SetInvalid(size);
	}
	if (context.context.query_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(chunk.data[col++]);
		client_context_data[size] = context.context.query_id.GetIndex();
	} else {
		FlatVector::Validity(chunk.data[col++]).SetInvalid(size);
	}

	if (context.context.thread_id.IsValid()) {
		auto thread_data = FlatVector::GetData<idx_t>(chunk.data[col++]);
		thread_data[size] = context.context.thread_id.GetIndex();
	} else {
		FlatVector::Validity(chunk.data[col++]).SetInvalid(size);
	}

	chunk.SetCardinality(size + 1);
}

void BufferingLogStorage::WriteLogEntry(timestamp_t timestamp, LogLevel level, const string &log_type,
                                       const string &log_message, const RegisteredLoggingContext &context) {
	unique_lock<mutex> lck(lock);

	if (registered_contexts.find(context.context_id) == registered_contexts.end()) {
		WriteLoggingContext(context);
	}

	auto size = log_entries_buffer->size();

	idx_t col = 0;

	if (normalize_contexts) {
		auto context_id_data = FlatVector::GetData<idx_t>(log_entries_buffer->data[col++]);
		context_id_data[size] = context.context_id;
	} else {
		WriteLoggingContextsToChunk(*log_entries_buffer, context, col);
	}

	auto timestamp_data = FlatVector::GetData<timestamp_t>(log_entries_buffer->data[col++]);
	timestamp_data[size] = timestamp;

	auto type_data = FlatVector::GetData<string_t>(log_entries_buffer->data[col]);
	type_data[size] = StringVector::AddString(log_entries_buffer->data[col++], log_type);

	auto level_data = FlatVector::GetData<string_t>(log_entries_buffer->data[col]);
	level_data[size] = StringVector::AddString(log_entries_buffer->data[col++], EnumUtil::ToString(level)); // TODO: do cast on write out

	auto message_data = FlatVector::GetData<string_t>(log_entries_buffer->data[col]);
	message_data[size] = StringVector::AddString(log_entries_buffer->data[col++], log_message);

	log_entries_buffer->SetCardinality(size + 1);

	if (size + 1 >= max_buffer_size) {
		FlushInternal();
	}
}

void BufferingLogStorage::WriteLogEntries(DataChunk &chunk, const RegisteredLoggingContext &context) {
	throw NotImplementedException("BufferingLogStorage::WriteLogEntries(DataChunk &chunk) not implemented");
	unique_lock<mutex> lck(lock);
	log_entries_buffer->Append(chunk);

	// TODO: this overflows buffer?
	if (log_entries_buffer->size() >= max_buffer_size) {
		FlushInternal();
	}
}

void BufferingLogStorage::Flush() {
	unique_lock<mutex> lck(lock);
	FlushInternal();
}

void BufferingLogStorage::Truncate() {
	unique_lock<mutex> lck(lock);
	ResetBuffers();
}

void InMemoryLogStorage::Truncate() {
	unique_lock<mutex> lck(lock);
	ResetBuffers();
}

void InMemoryLogStorage::FlushInternal() {
	if (log_entries_buffer->size() > 0) {
		log_entries->Append(*log_entries_buffer);
		log_entries_buffer->Reset();
	}

	if (log_contexts_buffer->size() > 0) {
		log_contexts->Append(*log_contexts_buffer);
		log_contexts_buffer->Reset();
	}
}

void BufferingLogStorage::WriteLoggingContext(const RegisteredLoggingContext &context) {
	registered_contexts.insert(context.context_id);

	// If we don't normalize the contexts they are written out on every log entry
	if (!normalize_contexts) {
		return;
	}

	idx_t col = 0;
	WriteLoggingContextsToChunk(*log_contexts_buffer, context, col);

	if (log_contexts_buffer->size() >= max_buffer_size) {
		FlushInternal();
	}
}

void BufferingLogStorage::ResetBuffers() {
	log_entries_buffer->Reset();
	log_contexts_buffer->Reset();
	registered_contexts.clear();
}

bool InMemoryLogStorage::CanScan() {
	return true;
}

unique_ptr<LogStorageScanState> InMemoryLogStorage::CreateScanEntriesState() const {
	return make_uniq<InMemoryLogStorageScanState>();
}
bool InMemoryLogStorage::ScanEntries(LogStorageScanState &state, DataChunk &result) const {
	unique_lock<mutex> lck(lock);
	auto &in_mem_scan_state = state.Cast<InMemoryLogStorageScanState>();
	return log_entries->Scan(in_mem_scan_state.scan_state, result);
}

void InMemoryLogStorage::InitializeScanEntries(LogStorageScanState &state) const {
	unique_lock<mutex> lck(lock);
	auto &in_mem_scan_state = state.Cast<InMemoryLogStorageScanState>();
	log_entries->InitializeScan(in_mem_scan_state.scan_state, ColumnDataScanProperties::DISALLOW_ZERO_COPY);
}

unique_ptr<LogStorageScanState> InMemoryLogStorage::CreateScanContextsState() const {
	return make_uniq<InMemoryLogStorageScanState>();
}
bool InMemoryLogStorage::ScanContexts(LogStorageScanState &state, DataChunk &result) const {
	unique_lock<mutex> lck(lock);
	auto &in_mem_scan_state = state.Cast<InMemoryLogStorageScanState>();
	return log_contexts->Scan(in_mem_scan_state.scan_state, result);
}

void InMemoryLogStorage::InitializeScanContexts(LogStorageScanState &state) const {
	unique_lock<mutex> lck(lock);
	auto &in_mem_scan_state = state.Cast<InMemoryLogStorageScanState>();
	log_contexts->InitializeScan(in_mem_scan_state.scan_state, ColumnDataScanProperties::DISALLOW_ZERO_COPY);
}

} // namespace duckdb
