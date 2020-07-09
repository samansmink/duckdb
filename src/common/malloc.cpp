#include "duckdb/common/malloc.hpp"

#include <limits>
namespace duckdb {

void* (*custom_malloc)(size_t size) = nullptr;
void (*custom_free)(void* buf) = nullptr;

} // namespace duckdb
