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

find_library(LIBOS_LIBRARY libos HINTS /home/sam/Documents/graphene/LibOS/glibc-build/libos)

add_executable(benchmark_runner benchmark_runner.cpp ${BENCHMARK_OBJECT_FILES})
target_link_libraries(benchmark_runner
                      duckdb
                      dbgen
                      dsdgen
                      imdb
                      test_helpers
                      tpce
                      ${LIBOS_LIBRARY}
                      sqlite_transfer)
