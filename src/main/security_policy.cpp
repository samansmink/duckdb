#include "duckdb/main/security_policy.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {

SecurityPolicy::SecurityPolicy(SecurityMode mode_p, set<string> allowed_directories_p,
                               unordered_set<string> allowed_paths_p)
    : mode(mode_p), allowed_directories(std::move(allowed_directories_p)), allowed_paths(std::move(allowed_paths_p)) {
}

bool SecurityPolicy::PathIsAllowed(string path, FileType type, const unordered_set<string> &allowed_paths,
                                   const set<string> &allowed_directories) {
	if (allowed_paths.count(path) > 0) {
		return true;
	}
	if (type == FileType::FILE_TYPE_DIR && !StringUtil::EndsWith(path, "/")) {
		path += "/";
	}
	for (const auto &allowed_directory : allowed_directories) {
		D_ASSERT(StringUtil::EndsWith(allowed_directory, "/"));
		if (StringUtil::StartsWith(path, allowed_directory)) {
			return true;
		}
	}
	return false;
}

bool SecurityPolicy::CanAccessFile(const string &path, FileType type) const {
	if (!IsSecure()) {
		return true;
	}
	return PathIsAllowed(path, type, allowed_paths, allowed_directories);
}

void SecurityPolicy::VerifyCanInstallExtension(const string &extension) const {
	if (!IsSecure()) {
		return;
	}
	throw NotImplementedException("Cannot install extension \"%s\" in secure mode - extension grants are not "
	                              "implemented yet",
	                              extension);
}

} // namespace duckdb
