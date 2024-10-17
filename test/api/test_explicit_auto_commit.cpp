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

static void CheckSimpleQuery(Connection &con) {
	auto prepare = con.Prepare("SELECT COUNT(*) FROM a WHERE i=$1");
	auto result = prepare->Execute(12);
	REQUIRE(CHECK_COLUMN(result, 0, {1}));
	auto result2 = prepare->Execute(14);
	REQUIRE(CHECK_COLUMN(result2, 0, {0}));
}

static void CheckSimpleQueryAfterAppend(Connection &con) {
	auto prepare = con.Prepare("SELECT COUNT(*) FROM a WHERE i=$1");
	auto result = prepare->Execute(12);
	REQUIRE(CHECK_COLUMN(result, 0, {1}));
	auto result2 = prepare->Execute(14);
	REQUIRE(CHECK_COLUMN(result2, 0, {1}));
}


TEST_CASE("Test explicit auto commit", "[api]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	Connection con(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	CreateSimpleTable(con);

	///// Happy path: using explicit auto commit to run all queries in CheckSimpleQuery in single transaction
	auto_commit_state = con.context->StartExplicitAutoCommit();
	REQUIRE(con.context->transaction.RequiresExplicitAutoCommit());
	CheckSimpleQuery(con);
	con.context->FinishExplicitAutoCommit(*auto_commit_state);
	auto_commit_state = nullptr;

	///// Edge Case: AutoCommit was disabled when explicit autocommit was started
	// Set autocommit to false (will start transaction)
	con.SetAutoCommit(false);

	// Explicit autocommit is NOP
	auto_commit_state = con.context->StartExplicitAutoCommit();
	REQUIRE((auto_commit_state->result == AutoCommitResult::ALREADY_IN_TRANSACTION));
	REQUIRE(!con.context->transaction.RequiresExplicitAutoCommit());

	// Query will run in transaction started by con.SetAutoCommit(false);
	CheckSimpleQuery(con);

	con.context->FinishExplicitAutoCommit(*auto_commit_state);
	auto_commit_state = nullptr;

	// Clean up by committing the transaction started by con.SetAutoCommit(false) and restoring SetAutoCommit
	con.Commit();
	con.SetAutoCommit(true);

	// Ensure we left things in a clean state
	CheckSimpleQuery(con);
	REQUIRE(con.IsAutoCommit());
	REQUIRE(!con.context->transaction.RequiresExplicitAutoCommit());
}

TEST_CASE("Test explicit auto commit correctly isolates", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	Connection con2(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	CreateSimpleTable(con);
	CheckSimpleQuery(con);

	auto_commit_state = con.context->StartExplicitAutoCommit();
	CheckSimpleQuery(con);

	AppendToSimpleTable(con2);
	CheckSimpleQueryAfterAppend(con2);

	// Con can not yet see changes from con2 because of the explicit auto-commit
	CheckSimpleQuery(con);

	con.context->FinishExplicitAutoCommit(*auto_commit_state);

	// Now con CAN see the changes
	CheckSimpleQueryAfterAppend(con);
}

TEST_CASE("Test explicit auto commit correctly works when omitting FinishExplicitAutoCommit", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	Connection con2(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	CreateSimpleTable(con);
	CheckSimpleQuery(con);

	auto_commit_state = con.context->StartExplicitAutoCommit();
	CheckSimpleQuery(con);

	AppendToSimpleTable(con2);
	CheckSimpleQueryAfterAppend(con2);

	// Con can not yet see changes from con2 because of the explicit auto-commit
	CheckSimpleQuery(con);

	// This also works but ideally FinishExplicitAutoCommit should be called explicitly
	auto_commit_state = nullptr;

	// Now con CAN see the changes
	CheckSimpleQueryAfterAppend(con);
}

TEST_CASE("Test explicit auto commit handles transactions correctly", "[api]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	Connection con(db);
	Connection con2(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	CreateSimpleTable(con);
	CheckSimpleQuery(con);

	// Starting a transaction during explicit autocommit is fine!
	auto_commit_state = con.context->StartExplicitAutoCommit();

	con.BeginTransaction();
	CheckSimpleQuery(con);
	CheckSimpleQuery(con);
	con.Commit();

	// Note that starting a transaction will disable explicit auto commit
	D_ASSERT(con.context->transaction.IsAutoCommit());
	D_ASSERT(!con.context->transaction.HasActiveTransaction());
	D_ASSERT(!con.context->transaction.RequiresExplicitAutoCommit());

	AppendToSimpleTable(con2);
	CheckSimpleQueryAfterAppend(con2);

	// Change is directly visible since we are back in regular auto-commit mode
	CheckSimpleQueryAfterAppend(con);

	// This is a NOP: the original explicit auto commit transaction has ended the moment BeginTransaction was called
	con.context->FinishExplicitAutoCommit(*auto_commit_state);
}

TEST_CASE("Auto commit state outliving connection", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	CreateSimpleTable(con);
	CheckSimpleQuery(con);

	// Starting a transaction during explicit autocommit is fine!
	auto_commit_state = con.context->StartExplicitAutoCommit();

	CheckSimpleQuery(con);

	// Reset everything
	con = Connection(db);
	db = DuckDB(nullptr);

	// Trigger commit state destructor -> Should not crash
	auto_commit_state = nullptr;
}

// TODO: don't think this is streaming yet
TEST_CASE("Auto commit with streaming result", "[api]") {
	DuckDB db(nullptr);
	Connection con(db);
	duckdb::unique_ptr<AutoCommitState> auto_commit_state;
	con.EnableQueryVerification();

	con.Query("set streaming_buffer_size='1mb'");

	idx_t count = 10000;

	// auto_commit_state = con.context->StartExplicitAutoCommit();
	auto prepare = con.Prepare("create table tbl as from range(10000);");
	auto result = prepare->Execute();
	REQUIRE(!result->HasError());
	// con.context->FinishExplicitAutoCommit(*auto_commit_state);
	auto_commit_state = nullptr;

	auto_commit_state = con.context->StartExplicitAutoCommit();
	auto streaming_query = con.SendQuery("select * from tbl");
	REQUIRE(!streaming_query->HasError());
	con.context->FinishExplicitAutoCommit(*auto_commit_state);
	auto_commit_state = nullptr;

	duckdb::ColumnDataCollection collection(duckdb::Allocator::DefaultAllocator(), streaming_query->types);
	while (true) {
		printf("LOOPLOOP");
		auto chunk = streaming_query->Fetch();
		if (chunk) {
			collection.Append(*chunk);
		} else {
			break;
		}
	}

	REQUIRE(collection.Count() == count);
}