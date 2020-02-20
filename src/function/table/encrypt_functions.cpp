#include "duckdb/function/table/encrypt_functions.hpp"
#include "duckdb/parser/parsed_data/create_view_info.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/catalog/catalog.hpp"

using namespace std;

namespace duckdb {

void BuiltinFunctions::RegisterEncryptedTableFunctions() {
	AddFunction(TableFunction(
	    "encrypted_table", {}, {SQLType::INTEGER, SQLType::INTEGER},
	    {"value", "encrypted"}, encrypted_table_init, encrypted_table, nullptr));

	CreateViewInfo info;
	info.schema = DEFAULT_SCHEMA;
	info.view_name = "encrypted_table";
	info.replace = true;

	auto select = make_unique<SelectNode>();
	select->select_list.push_back(make_unique<StarExpression>());
	vector<unique_ptr<ParsedExpression>> children;

	auto function = make_unique<FunctionExpression>(DEFAULT_SCHEMA, "encrypted_table", children);
	auto function_expr = make_unique<TableFunctionRef>();
	function_expr->function = move(function);
	select->from_table = move(function_expr);
	info.query = move(select);
}

} // namespace duckdb
