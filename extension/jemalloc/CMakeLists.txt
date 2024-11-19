cmake_minimum_required(VERSION 2.8.12...3.29)

project(JemallocExtension)

include_directories(include)
include_directories(jemalloc/include)

add_subdirectory(jemalloc)

set(JEMALLOC_EXTENSION_FILES jemalloc_extension.cpp)
build_static_extension(jemalloc ${JEMALLOC_EXTENSION_FILES})
target_link_libraries(jemalloc_extension jemalloc "$<TARGET_OBJECTS:jemalloc>")
# we do not do build_loadable_extension here because jemalloc is static-only

install(
  TARGETS jemalloc_extension jemalloc
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
