#include "catch.hpp"
#include "test_helpers.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/common/enums/joinref_type.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/expression/function_expression.hpp"

using namespace duckdb;
using namespace std;

// This function demonstrates/tests how the TableFunction::bind_replace works.
// The bind_replace_demo function has two params: depth and name. It generates custom plan recursively by using
// bind_replace to replace its plan with a CROSS PRODUCT of two calls to itself, with the depth reduced by one. When the
// base case is reached, a regular bind is performed, allowing the table function to be called normally.
struct BindReplaceDemoFun {
	struct CustomFunctionData : public TableFunctionData {
		int64_t current_depth;
		string current_name;
		bool done = false;
	};

	static unique_ptr<FunctionData> Bind(ClientContext &context, TableFunctionBindInput &input,
	                                     vector<LogicalType> &return_types, vector<string> &names) {
		auto result = make_unique<BindReplaceDemoFun::CustomFunctionData>();

		result->current_depth = input.inputs[0].GetValue<int64_t>();
		result->current_name = input.inputs[1].ToString();

		return_types.emplace_back(LogicalType::BIGINT);
		names.emplace_back("depth_" + result->current_name);

		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("col_" + result->current_name);

		return std::move(result);
	}

	static unique_ptr<TableRef> BindReplace(ClientContext &context, TableFunctionBindInput &input) {
		auto result = make_unique<BindReplaceDemoFun::CustomFunctionData>();

		auto depth = input.inputs[0].GetValue<int64_t>();
		auto name = input.inputs[1].ToString();

		// While depth > 0, we will replace the plan with a CROSS JOIN between to sub-calls to the same function
		// resulting in a recursively bound query plan that will eventually result in the regular bind being called.
		if (depth > 0) {
			auto join_node = make_unique<JoinRef>(JoinRefType::CROSS);

			// Construct LHS TableFunctionRef
			vector<unique_ptr<ParsedExpression>> left_children;
			left_children.push_back(make_unique<ConstantExpression>(Value(depth - 1)));
			left_children.push_back(make_unique<ConstantExpression>(Value(name + "L")));
			auto tf_ref_left = make_unique<TableFunctionRef>();
			tf_ref_left->alias = "inner_table_" + name + "L";
			tf_ref_left->function = make_unique<FunctionExpression>("bind_replace_demo", std::move(left_children));
			join_node->left = std::move(tf_ref_left);

			// Construct RHS TableFunctionRef
			vector<unique_ptr<ParsedExpression>> right_children;
			right_children.push_back(make_unique<ConstantExpression>(Value(depth - 1)));
			right_children.push_back(make_unique<ConstantExpression>(Value(name + "R")));
			auto tf_ref_right = make_unique<TableFunctionRef>();
			tf_ref_right->alias = "inner_table_" + name + "R";
			tf_ref_right->function = make_unique<FunctionExpression>("bind_replace_demo", std::move(right_children));
			join_node->right = std::move(tf_ref_right);

			return std::move(join_node);

		} else {
			// Recursion base case: instead of the bind replace, we return nullptr to indicate this time we do want to
			// do a regular bind phase
			return nullptr;
		}
	}

	static void Function(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
		auto &state = (BindReplaceDemoFun::CustomFunctionData &)*data.bind_data;

		if (!state.done) {
			output.SetValue(0, 0, Value(state.current_depth));
			output.SetValue(1, 0, Value(state.current_name));
			output.SetCardinality(1);
			state.done = true;
		} else {
			output.SetCardinality(0);
		}
	}

	static void Register(Connection &con) {
		// Create our test TableFunction
		con.BeginTransaction();
		auto &client_context = *con.context;
		auto &catalog = Catalog::GetSystemCatalog(client_context);
		TableFunction bind_replace_demo("bind_replace_demo", {LogicalType::BIGINT, LogicalType::VARCHAR},
		                                BindReplaceDemoFun::Function, BindReplaceDemoFun::Bind);
		bind_replace_demo.bind_replace = BindReplaceDemoFun::BindReplace;
		CreateTableFunctionInfo bind_replace_demo_info(bind_replace_demo);
		catalog.CreateTableFunction(*con.context, &bind_replace_demo_info);
		con.Commit();
	}
};

TEST_CASE("Bind Replace function", "[bind replace]") {
	DuckDB db(nullptr);
	Connection con(db);
	BindReplaceDemoFun::Register(con);

	auto result = con.Query("DESCRIBE SELECT * FROM bind_replace_demo(2, 'hello_');");
	REQUIRE(result->RowCount() == 8);
	REQUIRE(CHECK_COLUMN(result, 0,
	                     {"depth_hello_LL", "col_hello_LL", "depth_hello_LR", "col_hello_LR", "depth_hello_RL",
	                      "col_hello_RL", "depth_hello_RR", "col_hello_RR"}));

	auto result2 = con.Query("SELECT depth_hello_LL, col_hello_LL FROM bind_replace_demo(2, 'hello_');");
	REQUIRE(result2->RowCount() == 1);
	REQUIRE(CHECK_COLUMN(result2, 0, {0}));
	REQUIRE(CHECK_COLUMN(result2, 1, {"hello_LL"}));

	auto result3 = con.Query("EXPLAIN SELECT depth_hello_LL, col_hello_LL FROM bind_replace_demo(2, 'hello_');");
	Printer::Print(result3->ToString());
}
