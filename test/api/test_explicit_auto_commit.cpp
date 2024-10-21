#include "catch.hpp"
#include "test_helpers.hpp"

using namespace duckdb;
using namespace std;

static void CreateSimpleTable(Connection &con) {
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE a (i TINYINT)"));
	REQUIRE_NO_FAIL(con.Query("INSERT INTO a VALUES (11), (12), (13)"));
}

static void AppendToSimpleTable(Connection &con) {
	REQUIRE_NO_FAIL(con.Query("INSERT INTO a VALUES (14)"));
}

static void CheckSimpleQueryPrepareExecute(Connection &con) {
	auto statements = con.ExtractStatements("SELECT COUNT(*) FROM a WHERE i=?");
	REQUIRE(statements.size() == 1);
	duckdb::vector<Value> values = {Value(12)};
	auto result = con.PrepareAndExecute(std::move(statements[0]), values, true);
	REQUIRE(CHECK_COLUMN(result, 0, {1}));
}

static void CheckSimpleQueryAfterAppend(Connection &con) {
	auto statements = con.ExtractStatements("SELECT COUNT(*) FROM a WHERE i=?");
	REQUIRE(statements.size() == 1);
	REQUIRE(statements[0] != nullptr);

	duckdb::vector<Value> values = {Value(14)};
	auto result = con.PrepareAndExecute(std::move(statements[0]), values, true);
	REQUIRE(CHECK_COLUMN(result, 0, {1}));
}

TEST_CASE("PrepareExecute happy path", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	con.EnableQueryVerification();

	CreateSimpleTable(con);
	CheckSimpleQueryPrepareExecute(con);
	CheckSimpleQueryPrepareExecute(con);
}

TEST_CASE("PrepareExecute catalog error", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	con.EnableQueryVerification();

	CreateSimpleTable(con);

	// Check query with invalid table name
	auto statements = con.ExtractStatements("SELECT COUNT(*) FROM b WHERE i=?");
	REQUIRE(statements.size() == 1);
	duckdb::vector<Value> values = {Value(12)};
	auto result = con.PrepareAndExecute(std::move(statements[0]), values, true);
	D_ASSERT(result->HasError() && result->GetErrorType() == ExceptionType::CATALOG);

	// Verify things are still sane
	CheckSimpleQueryPrepareExecute(con);
}

TEST_CASE("PrepareExecute invalid value type error", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	con.EnableQueryVerification();

	CreateSimpleTable(con);

	// Check query with invalid prepared value
	auto statements = con.ExtractStatements("SELECT COUNT(*) FROM a WHERE i=?");
	REQUIRE(statements.size() == 1);
	duckdb::vector<Value> values = {Value("fawakaaniffoo")};
	auto result = con.PrepareAndExecute(std::move(statements[0]), values, true);
	D_ASSERT(result->HasError() && result->GetErrorType() == ExceptionType::CONVERSION);

	// Verify things are still sane
	CheckSimpleQueryPrepareExecute(con);
}