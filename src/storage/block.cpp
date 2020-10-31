#include "duckdb/storage/block.hpp"

using namespace duckdb;
using namespace std;

Block::Block(block_id_t id, bool unsecure) : FileBuffer(FileBufferType::BLOCK, Storage::BLOCK_ALLOC_SIZE, unsecure), id(id) {
}
