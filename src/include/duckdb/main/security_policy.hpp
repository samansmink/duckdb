//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/main/security_policy.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/enums/security_mode.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/set.hpp"
#include "duckdb/common/unordered_set.hpp"

namespace duckdb {

//! The security policy of a database instance: fixed when the database starts, read-only afterwards
class SecurityPolicy {
public:
	SecurityPolicy(SecurityMode mode, set<string> allowed_directories, unordered_set<string> allowed_paths);

	//! Whether a sanitized path is an allowed path, or lies inside an allowed directory
	static bool PathIsAllowed(string path, FileType type, const unordered_set<string> &allowed_paths,
	                          const set<string> &allowed_directories);

public:
	SecurityMode GetMode() const {
		return mode;
	}
	bool IsSecure() const {
		return mode == SecurityMode::SECURE;
	}
	const set<string> &GetAllowedDirectories() const {
		return allowed_directories;
	}
	const unordered_set<string> &GetAllowedPaths() const {
		return allowed_paths;
	}

	//! Whether the policy grants access to a sanitized path
	bool CanAccessFile(const string &path, FileType type) const;
	//! Throws if the policy does not allow installing an extension
	void VerifyCanInstallExtension(const string &extension) const;

private:
	const SecurityMode mode;
	//! Directories, and everything inside them, that the policy grants
	const set<string> allowed_directories;
	//! Files that the policy grants, including the files derived at startup such as the database and its WAL
	const unordered_set<string> allowed_paths;
};

} // namespace duckdb
