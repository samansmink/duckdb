cmake_policy(SET CMP0063 NEW)
include_directories(Unsecure)

file(COPY "libduck_enclave.a" DESTINATION ./)
file(COPY "duck_enclave.signed.so" DESTINATION ./../../)
file(COPY "duck_enclave.so" DESTINATION ./../../)

