//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/enums/security_mode.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/constants.hpp"

namespace duckdb {

enum class SecurityMode : uint8_t {
	//! SQL is trusted: no sandbox, and no settings that pretend to be one
	DEFAULT = 0,
	//! SQL is untrusted: access is limited to the policy fixed at startup
	SECURE = 1
};

} // namespace duckdb
