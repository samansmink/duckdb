#include "duckdb/common/file_buffer.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/checksum.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/aes.hpp"

#include <cstring>

using namespace duckdb;
using namespace std;

FileBuffer::FileBuffer(FileBufferType type, uint64_t bufsiz) : type(type) {
	const int SECTOR_SIZE = Storage::SECTOR_SIZE;
	// round up to the nearest SECTOR_SIZE, thi sis only really necessary if the file buffer will be used for Direct IO
	if (bufsiz % SECTOR_SIZE != 0) {
		bufsiz += SECTOR_SIZE - (bufsiz % SECTOR_SIZE);
	}
	assert(bufsiz % SECTOR_SIZE == 0);
	assert(bufsiz >= SECTOR_SIZE);
	// we add (SECTOR_SIZE - 1) to ensure that we can align the buffer to SECTOR_SIZE
	malloced_buffer = (data_ptr_t)malloc(bufsiz + (SECTOR_SIZE - 1));
	if (!malloced_buffer) {
		throw std::bad_alloc();
	}
	// round to multiple of SECTOR_SIZE
	uint64_t num = (uint64_t)malloced_buffer;
	uint64_t remainder = num % SECTOR_SIZE;
	if (remainder != 0) {
		num = num + SECTOR_SIZE - remainder;
	}
	assert(num % SECTOR_SIZE == 0);
	assert(num + bufsiz <= ((uint64_t)malloced_buffer + bufsiz + (SECTOR_SIZE - 1)));
	assert(num >= (uint64_t)malloced_buffer);
	// construct the FileBuffer object
	internal_buffer = (data_ptr_t)num;
	internal_size = bufsiz;
	buffer = internal_buffer + Storage::BLOCK_HEADER_SIZE;
	size = internal_size - Storage::BLOCK_HEADER_SIZE;
}

FileBuffer::~FileBuffer() {
	free(malloced_buffer);
}

// Abuse this to encrypt and decrypt?
void FileBuffer::Read(FileHandle &handle, uint64_t location) {

	if (Storage::ENCRYPT_STORAGE) {
        auto tmp_buffer = unique_ptr<unsigned char[]>{new unsigned char[internal_size]};
        auto tmp_data = tmp_buffer.get();

        // read the buffer from disk
        handle.Read(tmp_data, internal_size, location);

        auto aes_tag = tmp_data;
        tmp_data += TAG_SIZE;

        auto aes = AES();
        int decrypted_bytes = aes.Decrypt(tmp_data, internal_size - Storage::BLOCK_HEADER_SIZE,  aes_tag, internal_buffer + Storage::BLOCK_HEADER_SIZE);

        if (decrypted_bytes < 0) {
            throw IOException("Could not read database file: decryption failed, either key is wrong or file is corrupt");
        }

	} else {

        // read the buffer from disk
        handle.Read(internal_buffer, internal_size, location);

        // compute the checksum
        uint64_t stored_checksum = *((uint64_t *)internal_buffer);
        uint64_t computed_checksum = Checksum(buffer, size);
        // verify the checksum
        if (stored_checksum != computed_checksum) {
            throw IOException("Corrupt database file: computed checksum %llu does not match stored checksum %llu in block",
                              computed_checksum, stored_checksum);
        }
	}
}

void FileBuffer::Write(FileHandle &handle, uint64_t location) {

    if (Storage::ENCRYPT_STORAGE) {
        auto tmp_buffer = unique_ptr<unsigned char[]>{new unsigned char[internal_size]};
        auto tmp_data = tmp_buffer.get();

        auto aes_tag = tmp_data;
        tmp_data += TAG_SIZE;

        auto aes = AES();

        int encrypted_bytes = aes.Encrypt(internal_buffer + Storage::BLOCK_HEADER_SIZE, internal_size - Storage::BLOCK_HEADER_SIZE, tmp_data, aes_tag );

        if (encrypted_bytes < 0) {
            throw FatalException("Vector encryption failed");
        }

        handle.Write(aes_tag, internal_size, location);
    } else {
        // compute the checksum and write it to the start of the buffer
        uint64_t checksum = Checksum(buffer, size);
        *((uint64_t *)internal_buffer) = checksum;
        // now write the buffer
        handle.Write(internal_buffer, internal_size, location);
    }
}

void FileBuffer::Clear() {
	memset(internal_buffer, 0, internal_size);
}
