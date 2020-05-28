//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/storage/encrypted_segment.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/storage/table/column_segment.hpp"
#include "duckdb/storage/block.hpp"
#include "duckdb/storage/storage_lock.hpp"
#include "duckdb/storage/table/scan_state.hpp"

namespace duckdb {

//! An encrypted segment represents an encrypted segment of a column residing in a block
class EncryptedSegment : public UncompressedSegment {
public:
    using UncompressedSegment::UncompressedSegment;
    virtual ~EncryptedSegment();
private:

};

} // namespace duckdb
