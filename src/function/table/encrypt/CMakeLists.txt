add_library_unity(duckdb_func_encrypt
                  OBJECT
                  encrypted_table.cpp)
set(ALL_OBJECT_FILES
    ${ALL_OBJECT_FILES} $<TARGET_OBJECTS:duckdb_func_encrypt>
    PARENT_SCOPE)
