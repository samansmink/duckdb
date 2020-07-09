include_directories(../third_party/catch)
include_directories(../third_party/tpce-tool/include)
include_directories(../third_party/sqlite/include)
include_directories(../test/include)
include_directories(../tools/dbtransfer/include)
include_directories(include)
include_directories(/home/sam/Documents/graphene/LibOS/shim/include)

add_subdirectory(dbwrapper)
add_subdirectory(micro)
add_subdirectory(tpch)
add_subdirectory(tpcds)
add_subdirectory(imdb)
add_subdirectory(expression_reordering)

add_library(libos SHARED IMPORTED)
set_property(TARGET libos PROPERTY IMPORTED_LOCATION "/home/sam/Documents/graphene/LibOS/glibc-build/libos/liblibos.so")

add_executable(benchmark_runner benchmark_runner.cpp ${BENCHMARK_OBJECT_FILES})
target_link_libraries(benchmark_runner
                      duckdb
                      dbgen
                      dsdgen
                      imdb
                      test_helpers
                      tpce
                      sqlite_transfer)
