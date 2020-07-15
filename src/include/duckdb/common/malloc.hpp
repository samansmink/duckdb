//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/malloc.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once
#ifndef CUSTOM_MALLOC_H
#define CUSTOM_MALLOC_H

#include <stdarg.h>

namespace duckdb {
    extern void* (*custom_malloc)(size_t size);
    extern void (*custom_free)(void* buf);
} // namespace duckdb
#endif