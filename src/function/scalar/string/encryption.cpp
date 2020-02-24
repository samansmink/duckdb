#include "duckdb/common/aes.hpp"
#include "duckdb/common/base64.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/function/scalar/string_functions.hpp"

using namespace std;

namespace duckdb {

static const char *encrypt_scalar_function(const char *input_string, unique_ptr<char[]> &output) {

    index_t input_len = strlen(input_string);
	index_t encryption_buffer_size = Base64encode_len(input_len); // we're not using padding so encrypted len = plaintext len

	auto encryption_buffer = unique_ptr<char[]>{new char[encryption_buffer_size]};
	unsigned char tag[TAG_SIZE];

	auto aes = AES();

	int encrypted_bytes = aes.Encrypt((unsigned char *)input_string, input_len, (unsigned char*) encryption_buffer.get(), tag);
	int encoded_length = Base64encode_len(encrypted_bytes);
	int encoded_tag_length = Base64encode_len(TAG_SIZE);

	// Create new string of size encrypted_bytes
	output = unique_ptr<char[]>{new char[encoded_length + encoded_tag_length]};

	Base64encode(output.get(), (const char *)encryption_buffer.get(), encrypted_bytes);

	// -1 to overwrite null char and append directly to encrypted str
	Base64encode(&output[encoded_length - 1], (const char *)tag, TAG_SIZE);

	return output.get();
}

static const char *decrypt_scalar_function(const char *input_string, unique_ptr<char[]> &output) {

	unsigned char tag[TAG_SIZE];
	index_t input_string_len = strlen(input_string);
	output =  unique_ptr<char[]>{new char[input_string_len]};

    // memory size of these could be smaller, but Base64decodelen is quite heavy
	auto decoding_buffer = unique_ptr<char[]>{new char[input_string_len]};
	auto encoded_buffer = unique_ptr<char[]>{new char[input_string_len]};

	auto aes = AES();

	const char* tagAddr = &input_string[input_string_len - TAG_SIZE_ENCODED + 1];

	Base64decode((char*)tag, tagAddr);

	memcpy(encoded_buffer.get(), input_string, input_string_len - TAG_SIZE_ENCODED + 1);
	encoded_buffer[input_string_len - TAG_SIZE_ENCODED + 1] = '\0';

    int decode_len = Base64decode((char*)decoding_buffer.get(), (char*)encoded_buffer.get());
    int decrypted_length = aes.Decrypt((unsigned char*)decoding_buffer.get(), decode_len, tag,(unsigned char *)output.get());

    if (decrypted_length > 0) {
        output[decrypted_length] = '\0';
    } else {
        output[0] = '\0'; // TODO outputting NULL might be nicer?
    }

	return output.get();
}

static void encrypt(DataChunk &args, ExpressionState &state, Vector &result) {
	assert(args.column_count == 1 && args.data[0].type == TypeId::VARCHAR);
	auto &input_vector = args.data[0];

	unique_ptr<char[]> output;

	UnaryExecutor::Execute<const char *, const char *, true>(input_vector, result, [&](const char *input_string) {
		return result.AddString(encrypt_scalar_function(input_string, output));
	});
}

static void decrypt(DataChunk &args, ExpressionState &state, Vector &result) {
	assert(args.column_count == 1 && args.data[0].type == TypeId::VARCHAR);
	auto &input_vector = args.data[0];

	unique_ptr<char[]> output;

	UnaryExecutor::Execute<const char *, const char *, true>(input_vector, result, [&](const char *input_string) {
		return result.AddString(decrypt_scalar_function(input_string, output));
	});
}

void EncryptionFun::RegisterFunction(BuiltinFunctions &set) {
	set.AddFunction(ScalarFunction("encrypt", {SQLType::VARCHAR}, SQLType::VARCHAR, encrypt));
	set.AddFunction(ScalarFunction("decrypt", {SQLType::VARCHAR}, SQLType::VARCHAR, decrypt));
}

} // namespace duckdb
