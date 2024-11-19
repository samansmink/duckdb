include_directories(include)
include_directories(include/dsdgen-c)
add_subdirectory(dsdgen-c)

add_library(dsdgen OBJECT dsdgen.cpp append_info-c.cpp dsdgen_helpers.cpp)

disable_target_warnings(dsdgen)
