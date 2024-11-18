cmake_minimum_required(VERSION 2.8.12...3.29)

project(TpcdsExtension)

include_directories(include)
include_directories(dsdgen/include)
add_subdirectory(dsdgen)

build_static_extension(tpcds tpcds_extension.cpp ${DSDGEN_OBJECT_FILES})
target_link_libraries(tpcds_extension dsdgen "$<TARGET_OBJECTS:dsdgen>")
target_link_libraries(tpcds_extension dsdgen_c "$<TARGET_OBJECTS:dsdgen_c>")
set(PARAMETERS "-warnings")
build_loadable_extension(tpcds ${PARAMETERS} tpcds_extension.cpp
                         ${DSDGEN_OBJECT_FILES})

install(
  TARGETS tpcds_extension dsdgen dsdgen_c
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
