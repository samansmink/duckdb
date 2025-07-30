//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/csv_utils.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/execution/operator/csv_scanner/csv_reader_options.hpp"
#include "serializer/memory_stream.hpp"

namespace duckdb {
class MemoryStream;

struct CSVWriterOptions {
	//! The newline string to write
	string newline = "\n";
	//! The size of the CSV file (in bytes) that we buffer before we flush it to disk
	idx_t flush_size = 4096ULL * 8ULL;
	//! For each byte whether the CSV file requires quotes when containing the byte
	unsafe_unique_array<bool> requires_quotes;
};

struct CSVWriterLocalState {
	CSVWriterLocalState(ClientContext &context);
	CSVWriterLocalState(DatabaseInstance &db);
	CSVWriterLocalState();
	~CSVWriterLocalState();

	void Reset() {
		stream->Rewind();
		written_anything = false;
	}

	unique_ptr<MemoryStream> stream;
	bool written_anything = false;

	bool require_manual_flush = false;
};

struct CSVWriter {
	//! Create a CSVWriter that writes to a WriteStream
	CSVWriter(WriteStream &stream, vector<string> name_list);

	//! Create a CSVWriter that writes to a file
	CSVWriter(FileSystem &fs, const string &file_path, FileCompressionType compression);
	CSVWriter(CSVReaderOptions &options, FileSystem &fs, const string &file_path, FileCompressionType compression);

	//! Writes the raw string directly into the output stream
	void WriteRawString(const string& data);
	//! Writes the header directly into the output stream
	void WriteHeader();
	//! Write the Raw String, using the local_state
	void WriteRawString(const string& prefix, CSVWriterLocalState &local_state);
	void WriteChunk(DataChunk &input, CSVWriterLocalState &local_state);

	void Flush(CSVWriterLocalState &local_state);

	// Resets the state of the writer. Warning: the file_writer is not reset
	void Reset(optional_ptr<CSVWriterLocalState> local_state);

	//! Closes
	void Close();

	unique_ptr<CSVWriterLocalState> InitializeLocalWriteState(ClientContext &context);
	unique_ptr<CSVWriterLocalState> InitializeLocalWriteState(DatabaseInstance &db);

	vector<unique_ptr<Expression>> string_casts;

	idx_t BytesWritten();

	bool WrittenAnything() {
		return written_anything;
	}

	CSVWriterOptions writer_options;
	CSVReaderOptions options;

protected:
	//! If we've written any rows yet, allows us to prevent a trailing comma when writing JSON ARRAY
	bool written_anything = false;

	//! (optional, the owned file writer of this CSVWriter)
	unique_ptr<BufferedFileWriter> file_writer;
	//! WriteStream to write output t (either the owned BufferedFileWriter, or an externally managed WriteStream)
	WriteStream &write_stream;

	idx_t bytes_written = 0;

	mutex lock;

	void FlushInternal(CSVWriterLocalState &local_state);

public:
	static void WriteQuoteOrEscape(WriteStream &writer, char quote_or_escape);
	static string AddEscapes(char to_be_escaped, char escape, const string &val);
	static bool RequiresQuotes(const char *str, idx_t len, vector<string> &null_str,
	                           unsafe_unique_array<bool> &requires_quotes);
	static void WriteQuotedString(WriteStream &writer, const char *str, idx_t len, bool force_quote,
	                              vector<string> &null_str, unsafe_unique_array<bool> &requires_quotes, char quote,
	                              char escape);
	static void WriteQuotedString(WriteStream &writer, const char *str, idx_t len, idx_t col_idx, CSVReaderOptions &options, CSVWriterOptions &writer_options);

	static void WriteChunk(DataChunk &input, MemoryStream &writer, CSVReaderOptions &options, bool &written_anything, CSVWriterOptions &writer_options);
	static void WriteHeader(MemoryStream &stream, CSVReaderOptions &options, CSVWriterOptions &writer_options);
};

} // namespace duckdb
