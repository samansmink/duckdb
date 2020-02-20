//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/function/table/sqlite_functions.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/function/table_function.hpp"

namespace duckdb {

FunctionData *encrypted_table_init(ClientContext &);
void encrypted_table(ClientContext &, DataChunk &input, DataChunk &output, FunctionData *dataptr);

} // namespace duckdb
