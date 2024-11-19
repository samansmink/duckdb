include_directories(include)


add_library(dbgen OBJECT
  dbgen.cpp
  dbgen_gunk.cpp
  bm_utils.cpp
  build.cpp
  permute.cpp
  rnd.cpp
  rng64.cpp
  speed_seed.cpp
  text.cpp)

disable_target_warnings(dbgen)
