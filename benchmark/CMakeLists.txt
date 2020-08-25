include_directories(../third_party/catch)
include_directories(../third_party/tpce-tool/include)
include_directories(../third_party/sqlite/include)
include_directories(../test/include)
include_directories(../tools/dbtransfer/include)
include_directories(include)

add_subdirectory(dbwrapper)
add_subdirectory(micro)
add_subdirectory(tpch)
add_subdirectory(tpcds)
add_subdirectory(imdb)
add_subdirectory(expression_reordering)

# Hacky solution to get it working with switchless enclave
find_library(SGXSWITCHLESS_LIB NAMES libsgx_uswitchless.a)

add_executable(benchmark_runner benchmark_runner.cpp ${BENCHMARK_OBJECT_FILES})
target_link_libraries(benchmark_runner
                      duckdb
                      dbgen
                      dsdgen
                      imdb
                      test_helpers
                      tpce
                      sqlite_transfer
                    "-Wl,--whole-archive"
                    ${SGXSWITCHLESS_LIB}
                    "-Wl,--no-whole-archive")
