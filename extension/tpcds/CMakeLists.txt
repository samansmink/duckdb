cmake_minimum_required(VERSION 2.8.12...3.29)

project(TpcdsExtension)

include_directories(include)
include_directories(dsdgen/include)
add_subdirectory(dsdgen)

build_static_extension(tpcds tpcds_extension.cpp)
target_sources(tpcds_extension INTERFACE $<TARGET_OBJECTS:dsdgen>)
target_sources(tpcds_extension INTERFACE $<TARGET_OBJECTS:dsdgen_c>)

set(PARAMETERS "-warnings")
build_loadable_extension(tpcds ${PARAMETERS} tpcds_extension.cpp $<TARGET_OBJECTS:dsdgen> $<TARGET_OBJECTS:dsdgen_c>)

install(
  TARGETS tpcds_extension dsdgen dsdgen_c
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
