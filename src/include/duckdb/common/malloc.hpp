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

    struct CustomDeleter { void operator()(data_t* p) { custom_free(p);} };
	template <class ObjType> struct CustomObjDeleter { void operator()(ObjType* p) {p->~ObjType();custom_free(p);p=NULL;}};
} // namespace duckdb
#endif