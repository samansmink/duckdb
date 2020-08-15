//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/file_buffer.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

extern "C" {
#include "chacha.h"
};

namespace duckdb {

struct EnclaveExecutor {
    static void InitializeEnclave();
    static void DestroyEnclave();
    static bool BinaryExecutor();
    static bool AggregateExecutor();
    static bool InitMinMax();
    static bool GetMinMax();
    static bool SetMinMax();
};
}