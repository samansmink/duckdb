#include "catch.hpp"
#include "test_helpers.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/main/security_policy.hpp"

using namespace duckdb;

namespace {

struct SecureModeFiles {
	SecureModeFiles() {
		allowed_dir = TestCreatePath("secure_mode_allowed");
		other_dir = TestCreatePath("secure_mode_other");
		TestCreateDirectory(allowed_dir);
		TestCreateDirectory(other_dir);
		allowed_file = allowed_dir + "/data.csv";
		other_file = other_dir + "/data.csv";
		Connection con(db);
		REQUIRE_NO_FAIL(con.Query("COPY (SELECT 42 AS i) TO '" + allowed_file + "'"));
		REQUIRE_NO_FAIL(con.Query("COPY (SELECT 84 AS i) TO '" + other_file + "'"));
	}

	DuckDB db {nullptr};
	string allowed_dir;
	string other_dir;
	string allowed_file;
	string other_file;
};

unique_ptr<DuckDB> OpenSecure(const vector<std::pair<string, Value>> &options) {
	DBConfig config;
	for (auto &option : options) {
		config.SetOptionByName(Identifier(option.first), option.second);
	}
	return make_uniq<DuckDB>(nullptr, &config);
}

Value List(const string &entry) {
	return Value::LIST(LogicalType::VARCHAR, {Value(entry)});
}

} // namespace

TEST_CASE("Secure mode grants policy paths given at startup", "[api][security_mode]") {
	SecureModeFiles files;
	auto db = OpenSecure({{"security_mode", Value("secure")}, {"allowed_directories", List(files.allowed_dir)}});
	Connection con(*db);

	auto result = con.Query("SELECT * FROM '" + files.allowed_file + "'");
	REQUIRE(CHECK_COLUMN(result, 0, {42}));
	result = con.Query("SELECT * FROM '" + files.other_file + "'");
	REQUIRE_FAIL(result);
	REQUIRE(StringUtil::Contains(result->GetError(), "file system operations are disabled by configuration"));

	result = con.Query("SELECT current_setting('enable_external_access')");
	REQUIRE(CHECK_COLUMN(result, 0, {false}));
}

TEST_CASE("Secure mode does not depend on the order of startup options", "[api][security_mode]") {
	SecureModeFiles files;
	auto db = OpenSecure({{"allowed_directories", List(files.allowed_dir)}, {"security_mode", Value("secure")}});
	Connection con(*db);

	auto result = con.Query("SELECT * FROM '" + files.allowed_file + "'");
	REQUIRE(CHECK_COLUMN(result, 0, {42}));
	REQUIRE_FAIL(con.Query("SELECT * FROM '" + files.other_file + "'"));
}

TEST_CASE("Secure mode rejects settings that it implies", "[api][security_mode]") {
	REQUIRE_THROWS_WITH(OpenSecure({{"security_mode", Value("secure")}, {"enable_external_access", Value(true)}}),
	                    Catch::Contains("cannot be enabled in secure mode"));
	REQUIRE_THROWS_WITH(OpenSecure({{"security_mode", Value("secure")}, {"lock_configuration", Value(true)}}),
	                    Catch::Contains("cannot be set in secure mode"));
	REQUIRE_NOTHROW(OpenSecure({{"security_mode", Value("secure")}, {"enable_external_access", Value(false)}}));
}

TEST_CASE("Policy settings are only available in secure mode", "[api][security_mode]") {
	REQUIRE_THROWS_WITH(OpenSecure({{"allowed_directories", List("/tmp")}}),
	                    Catch::Contains("only available in secure mode"));
}

TEST_CASE("Secure mode freezes settings that SQL may not change", "[api][security_mode]") {
	SecureModeFiles files;
	auto db = OpenSecure({{"security_mode", Value("secure")}, {"allowed_directories", List(files.allowed_dir)}});
	Connection con(*db);

	// secure_mode_only and secure_mode_frozen settings
	for (auto &statement :
	     {"SET allowed_directories=['/']", "RESET allowed_directories", "SET autoload_known_extensions=true",
	      "SET temp_directory='/tmp'", "SET enable_logging=true", "SET security_mode='default'"}) {
		auto result = con.Query(statement);
		REQUIRE_FAIL(result);
		REQUIRE(StringUtil::Contains(result->GetError(), "frozen in secure mode"));
	}
	// extension settings that do not declare their security are frozen
	REQUIRE_FAIL(con.Query("SET binary_as_string=true"));
	// SQL changeable settings, including declared extension settings
	REQUIRE_NO_FAIL(con.Query("SET threads=2"));
	REQUIRE_NO_FAIL(con.Query("SET search_path='main'"));
	REQUIRE_NO_FAIL(con.Query("SET TimeZone='UTC'"));

	// the C++ API cannot bypass the freeze
	auto &instance = *db->instance;
	auto option = DBConfig::GetOptionByName("allowed_directories");
	REQUIRE(option);
	REQUIRE_THROWS_WITH(instance.config.SetOption(&instance, *option, List("/")),
	                    Catch::Contains("frozen in secure mode"));
	REQUIRE_FAIL(con.Query("SELECT * FROM '" + files.other_file + "'"));

	// the mode itself is fixed by the policy, even when the setting is overwritten directly
	instance.config.SetOption(Identifier("security_mode"), Value("DEFAULT"));
	REQUIRE(instance.config.IsSecureMode());
	REQUIRE_FAIL(con.Query("SET autoload_known_extensions=true"));
}

TEST_CASE("Secure mode derives defaults from the mode", "[api][security_mode]") {
	auto db = OpenSecure({{"security_mode", Value("secure")}});
	Connection con(*db);
	auto result = con.Query("SELECT current_setting('autoinstall_known_extensions'), "
	                        "current_setting('autoload_known_extensions'), current_setting('temp_directory')");
	REQUIRE(CHECK_COLUMN(result, 0, {false}));
	REQUIRE(CHECK_COLUMN(result, 1, {false}));
	REQUIRE(CHECK_COLUMN(result, 2, {""}));

	// an explicit choice by the embedder is kept
	db = OpenSecure({{"security_mode", Value("secure")}, {"autoload_known_extensions", Value(true)}});
	Connection con2(*db);
	result = con2.Query("SELECT current_setting('autoload_known_extensions')");
	REQUIRE(CHECK_COLUMN(result, 0, {true}));
}

TEST_CASE("Default mode keeps the existing settings", "[api][security_mode]") {
	DuckDB db(nullptr);
	Connection con(db);
	REQUIRE_NO_FAIL(con.Query("SET allowed_directories=['/tmp']"));
	REQUIRE_NO_FAIL(con.Query("SET autoload_known_extensions=false"));
	REQUIRE_NO_FAIL(con.Query("SET enable_external_access=false"));
}

TEST_CASE("Secure mode policy is fixed at startup", "[api][security_mode]") {
	SecureModeFiles files;
	auto database_path = TestCreatePath("secure_mode.db");
	DBConfig config;
	config.SetOptionByName("security_mode", Value("secure"));
	config.SetOptionByName("allowed_directories", List(files.allowed_dir));
	DuckDB db(database_path, &config);
	Connection con(db);

	// the database file and its WAL are granted at startup
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE t AS SELECT 42 AS i"));
	REQUIRE_NO_FAIL(con.Query("CHECKPOINT"));
	REQUIRE_NO_FAIL(con.Query("ATTACH '" + files.allowed_dir + "/attached.db' AS attached"));
	REQUIRE_FAIL(con.Query("ATTACH '" + files.other_dir + "/attached.db' AS other"));

	// paths added to the mutable allowlists after startup are not part of the policy
	db.instance->config.AddAllowedPath(files.other_file);
	REQUIRE_FAIL(con.Query("SELECT * FROM '" + files.other_file + "'"));
	REQUIRE(db.instance->config.GetSecurityPolicy().IsSecure());

	// duckdb_settings() shows the effective policy, including the grants derived at startup
	auto result = con.Query("SELECT contains(value, 'secure_mode.db.wal'), contains(value, 'secure_mode_other') "
	                        "FROM duckdb_settings() WHERE name = 'allowed_paths'");
	REQUIRE(CHECK_COLUMN(result, 0, {true}));
	REQUIRE(CHECK_COLUMN(result, 1, {false}));

	result = con.Query("INSTALL some_extension");
	REQUIRE_FAIL(result);
	REQUIRE(StringUtil::Contains(result->GetError(), "extension grants are not implemented yet"));
}
