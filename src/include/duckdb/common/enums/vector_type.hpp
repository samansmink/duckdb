//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/enums/vector_type.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/constants.hpp"

namespace duckdb {

enum class VectorType : uint8_t {
	FLAT_VECTOR,            // Flat vectors represent a standard uncompressed vector
	CONSTANT_VECTOR,        // Constant vector represents a single constant
	DICTIONARY_VECTOR,      // Dictionary vector represents a selection vector on top of another vector
	SEQUENCE_VECTOR,        // Sequence vector represents a sequence with a start point and an increment
	SGX_VECTOR,              // SGX Vectors contain a buffer with the encrypted nullmask, encrypted data, and the IV for decryption.
	SGX_DICTIONARY_VECTOR   // A dictionary represents a selection vector on top of an SGX_VECTOR
};

string VectorTypeToString(VectorType type);

} // namespace duckdb
