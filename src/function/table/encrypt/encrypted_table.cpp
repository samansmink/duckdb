#include "duckdb/function/table/encrypt_functions.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include <algorithm>

using namespace std;

namespace duckdb {

// Note this doesn't actually encrypt anything yet. It was simply
// a try out to learn how the table producing functions work.
// I might use it later to figure out how to use it for my experiments

struct EncryptedTableData : public TableFunctionData {
    EncryptedTableData() {

        // fill values with bogus data
        for (int i  = 0; i < 10000; i++) {
			values.push_back(i);
		}
        offset = 0;
	}

	vector<int> values;
	index_t offset;
};

FunctionData *encrypted_table_init(ClientContext &context) {
	// initialize the function data structure
	return new EncryptedTableData();
}

void encrypted_table(ClientContext &context, DataChunk &input, DataChunk &output, FunctionData *dataptr) {
	auto &data = *((EncryptedTableData *)dataptr);

	if (data.offset >= data.values.size()) {
		return;
	}

	index_t next = min(data.offset + STANDARD_VECTOR_SIZE, (index_t)data.values.size());

	index_t output_count = next - data.offset;
	for (index_t j = 0; j < output.column_count; j++) {
		output.data[j].count = output_count;
	}
	// start returning values
	// either fill up the chunk or return all the remaining columns
	for (index_t i = data.offset; i < next; i++) {
		auto index = i - data.offset;
		auto value = data.values[i];
		output.data[0].SetValue(index, Value::INTEGER(value));
		output.data[1].SetValue(index, Value::INTEGER(value+1));
	}
	data.offset = next;

	output.data[0].Encrypt();
    output.data[1].Encrypt();
}

} // namespace duckdb
