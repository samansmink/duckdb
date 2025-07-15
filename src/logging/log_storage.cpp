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
}

void CSVLogStorage::UpdateConfig(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	lock_guard<mutex> lck(lock);
	return UpdateConfigInternal(db, config);
}

void CSVLogStorage::FlushInternal() {
	log_entries_writer->WriteChunk(*log_entries_buffer, *log_entries_state);
	log_entries_buffer->Reset();

	log_contexts_writer->WriteChunk(*log_contexts_buffer, *log_entries_state);
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
}

StdOutLogStorage::~StdOutLogStorage() {
}

void StdOutLogStorage::Truncate() {
	// NOP
}

void StdOutLogStorage::FlushInternal() {
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
	auto &fs = db.GetFileSystem();

	// TODO: make lazy again?
	InitializeLogEntriesFile(db);
	if (normalize_contexts) {
		InitializeLogContextsFile(db);
	}
	initialized = true;

	FileCompressionType compression = FileCompressionType::UNCOMPRESSED;

	log_entries_file_writer = make_uniq<BufferedFileWriter>(fs, GetDefaultLogEntriesFilePath(db), FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW | FileLockType::WRITE_LOCK | compression);
	log_contexts_file_writer = make_uniq<BufferedFileWriter>(fs, GetDefaultLogContextsFilePath(db), FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW | FileLockType::WRITE_LOCK | compression);

	// TODO: dedup
	log_entries_writer = make_uniq<CSVWriter>(*log_entries_file_writer, GetEntriesColumnNames(true));
	log_contexts_writer = make_uniq<CSVWriter>(*log_contexts_file_writer, GetContextsColumnNames());
	log_entries_state = log_entries_writer->InitializeLocalWriteState(db);
	log_contexts_state = log_contexts_writer->InitializeLocalWriteState(db);
}

FileLogStorage::~FileLogStorage() {
}

void FileLogStorage::WriteLogEntriesHeader() {
	log_entries_writer->WriteHeader();
	log_entries_should_write_header = false;

	// TODO: pass schema to writer
	// MemoryStream buffer;
	// WriteString(csv_config, buffer, "context_id");
	// if (!normalize_contexts) {
	// 	WriteString(csv_config, buffer, "scope");
	// 	WriteString(csv_config, buffer, "connection_id");
	// 	WriteString(csv_config, buffer, "transaction_id");
	// 	WriteString(csv_config, buffer, "query_id");
	// 	WriteString(csv_config, buffer, "thread_id");
	// }
	// WriteString(csv_config, buffer, "timestamp");
	// WriteString(csv_config, buffer, "log_level");
	// WriteString(csv_config, buffer, "type");
	// WriteString(csv_config, buffer, "message", false);
	// buffer.WriteData(const_data_ptr_cast(csv_config.newline.c_str()), csv_config.newline.size());
	// log_entries_file_handle->Write(buffer.GetData(), buffer.GetPosition());
	//
}

void FileLogStorage::WriteLogContextsHeader() {
	log_contexts_writer->WriteHeader();
	log_contexts_should_write_header = false;

	// TODO: pass schema to CSV writer
	// MemoryStream buffer;
	// WriteString(csv_config, buffer, "context_id");
	// WriteString(csv_config, buffer, "scope");
	// WriteString(csv_config, buffer, "connection_id");
	// WriteString(csv_config, buffer, "transaction_id");
	// WriteString(csv_config, buffer, "query_id");
	// WriteString(csv_config, buffer, "thread_id", false);
	// buffer.WriteData(const_data_ptr_cast(csv_config.newline.c_str()), csv_config.newline.size());
	// log_contexts_file_handle->Write(buffer.GetData(), buffer.GetPosition());
}

void FileLogStorage::InitializeLogContextsFile(DatabaseInstance &db, const string &path) {
	if (path.empty()) {
		return InitializeFile(db, GetDefaultLogContextsFilePath(db), log_contexts_should_write_header);
	}
	return InitializeFile(db, path, log_contexts_should_write_header);
}

void FileLogStorage::InitializeLogEntriesFile(DatabaseInstance &db, const string &path) {
	if (path.empty()) {
		return InitializeFile(db, GetDefaultLogEntriesFilePath(db), log_entries_should_write_header);
	}
	return InitializeFile(db, path, log_entries_should_write_header);
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

	log_entries_writer->Flush(*log_entries_state);
	log_entries_file_writer->Truncate(0);
	log_entries_writer->WriteHeader(); // TODO: is this correct?

	log_contexts_writer->Flush(*log_contexts_state);
	log_contexts_file_writer->Truncate(0);
	log_contexts_writer->WriteHeader(); // TODO: is this correct?

	// TODO: handle denormalized?
}

void FileLogStorage::FlushInternal() {
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

		log_contexts_writer->WriteChunk(*log_contexts_buffer, *log_contexts_state);
		log_contexts_writer->Flush(*log_contexts_state); // TODO: auto-flush on flushing storage?
		log_contexts_buffer->Reset();
	}

	if (log_entries_buffer->size() > 0) {
		// TODO: let CSV Writer handle?
		if (log_entries_should_write_header) {
			WriteLogEntriesHeader();
		}

		log_contexts_writer->WriteChunk(*log_entries_buffer, *log_entries_state);
		log_contexts_writer->Flush(*log_entries_state); // TODO: auto-flush on flushing storage?
		log_entries_buffer->Reset();
	}
}

void FileLogStorage::UpdateConfigInternal(DatabaseInstance &db, case_insensitive_map_t<Value> &config) {
	auto config_copy = config;

	string contexts_path;
	string entries_path;

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
		    "SELECT context_id::UBIGINT as context_id, timestamp::TIMESTAMP as timestamp, type::VARCHAR as type, "
		    "log_level::VARCHAR as log_level, message::VARCHAR as message");
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
		                           "transaction_id, query_id::UBIGINT as query_id, thread_id::UBIGINT as thread_id");
	}

	// When log contexts are denormalized in the csv files, we will be reading them horribly inefficiently by doing a
	// select DISTINCT on the log_entries_file_handle
	// TODO: fix? throw?
	return BindReplaceInternal(context, input, log_entries_file_writer->path,
	                           "SELECT DISTINCT context_id::UBIGINT as context_id, scope::VARCHAR as scope, "
	                           "connection_id::UBIGINT as connection_id, transaction_id::UBIGINT as transaction_id, "
	                           "query_id::UBIGINT as query_id, thread_id::UBIGINT as thread_id");
}

BufferingLogStorage::BufferingLogStorage(DatabaseInstance &db_p) {
	max_buffer_size = STANDARD_VECTOR_SIZE; // TODO dedup
	log_entries_buffer = make_uniq<DataChunk>();
	log_contexts_buffer = make_uniq<DataChunk>();
	log_entries_buffer->Initialize(Allocator::DefaultAllocator(), GetEntriesSchema(true), STANDARD_VECTOR_SIZE);
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

void BufferingLogStorage::WriteLogEntry(timestamp_t timestamp, LogLevel level, const string &log_type,
                                       const string &log_message, const RegisteredLoggingContext &context) {
	unique_lock<mutex> lck(lock);

	if (registered_contexts.find(context.context_id) == registered_contexts.end()) {
		WriteLoggingContext(context);
	}

	auto size = log_entries_buffer->size();
	auto context_id_data = FlatVector::GetData<idx_t>(log_entries_buffer->data[0]);
	auto timestamp_data = FlatVector::GetData<timestamp_t>(log_entries_buffer->data[1]);
	auto type_data = FlatVector::GetData<string_t>(log_entries_buffer->data[2]);
	auto level_data = FlatVector::GetData<string_t>(log_entries_buffer->data[3]);
	auto message_data = FlatVector::GetData<string_t>(log_entries_buffer->data[4]);

	context_id_data[size] = context.context_id;
	timestamp_data[size] = timestamp;
	type_data[size] = StringVector::AddString(log_entries_buffer->data[2], log_type);
	level_data[size] = StringVector::AddString(log_entries_buffer->data[3], EnumUtil::ToString(level));
	message_data[size] = StringVector::AddString(log_entries_buffer->data[4], log_message);

	log_entries_buffer->SetCardinality(size + 1);

	if (size + 1 >= max_buffer_size) {
		FlushInternal();
	}
}

void BufferingLogStorage::WriteLogEntries(DataChunk &chunk, const RegisteredLoggingContext &context) {
	throw NotImplementedException("BufferingLogStorage::WriteLogEntries(DataChunk &chunk) not implemented");
}


void BufferingLogStorage::Flush() {
	unique_lock<mutex> lck(lock);
	FlushInternal();
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

	auto size = log_contexts_buffer->size();

	auto context_id_data = FlatVector::GetData<idx_t>(log_contexts_buffer->data[0]);
	context_id_data[size] = context.context_id;

	auto context_scope_data = FlatVector::GetData<string_t>(log_contexts_buffer->data[1]);
	context_scope_data[size] =
	    StringVector::AddString(log_contexts_buffer->data[1], EnumUtil::ToString(context.context.scope));

	if (context.context.connection_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(log_contexts_buffer->data[2]);
		client_context_data[size] = context.context.connection_id.GetIndex();
	} else {
		FlatVector::Validity(log_contexts_buffer->data[2]).SetInvalid(size);
	}
	if (context.context.transaction_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(log_contexts_buffer->data[3]);
		client_context_data[size] = context.context.transaction_id.GetIndex();
	} else {
		FlatVector::Validity(log_contexts_buffer->data[3]).SetInvalid(size);
	}
	if (context.context.query_id.IsValid()) {
		auto client_context_data = FlatVector::GetData<idx_t>(log_contexts_buffer->data[4]);
		client_context_data[size] = context.context.query_id.GetIndex();
	} else {
		FlatVector::Validity(log_contexts_buffer->data[4]).SetInvalid(size);
	}

	if (context.context.thread_id.IsValid()) {
		auto thread_data = FlatVector::GetData<idx_t>(log_contexts_buffer->data[5]);
		thread_data[size] = context.context.thread_id.GetIndex();
	} else {
		FlatVector::Validity(log_contexts_buffer->data[5]).SetInvalid(size);
	}

	log_contexts_buffer->SetCardinality(size + 1);

	if (size + 1 >= max_buffer_size) {
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
