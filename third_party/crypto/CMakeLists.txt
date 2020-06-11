cmake_policy(SET CMP0063 NEW)
add_library(crypto STATIC chacha.c)

target_include_directories(fmt PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
set_target_properties(crypto PROPERTIES EXPORT_NAME duckdb_crypto)

install(TARGETS crypto
        EXPORT "${DUCKDB_EXPORT_SET}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")