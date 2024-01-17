#
# This config file holds all out-of-tree extension that are built with DuckDB's CI
#
# to build duckdb with this configuration run:
#   EXTENSION_CONFIGS=.github/config/out_of_tree_extensions.cmake make
#

################# ARROW
if (NOT WIN32)
    duckdb_extension_load(arrow
            LOAD_TESTS DONT_LINK
            GIT_URL https://github.com/duckdb/arrow
            GIT_TAG 1b5b9649d28cd7f79496fb3f2e4dd7b03bf90ac5
            APPLY_PATCHES
            )
endif()

################## AWS
if (NOT MINGW)
    duckdb_extension_load(aws
            LOAD_TESTS
            GIT_URL https://github.com/duckdb/duckdb_aws
            GIT_TAG a882a233abbef1d98277558074a90d3ff4b86ed4
            )
endif()

################# AZURE
if (NOT MINGW)
    duckdb_extension_load(azure
            LOAD_TESTS
            GIT_URL https://github.com/duckdb/duckdb_azure
            GIT_TAG 03a0878ba8be1f4dbe385652bbf96f4d3feef05d
            )
endif()

################# ICEBERG
# Windows tests for iceberg currently not working
if (NOT WIN32)
    set(LOAD_ICEBERG_TESTS "LOAD_TESTS")
else ()
    set(LOAD_ICEBERG_TESTS "")
endif()

if (NOT MINGW)
    duckdb_extension_load(iceberg
            ${LOAD_ICEBERG_TESTS}
            GIT_URL https://github.com/duckdb/duckdb_iceberg
            GIT_TAG 7aa3d8e4cb7b513d35fdacfa28dc328771bc4047
            )
endif()

################# POSTGRES_SCANNER
# Note: tests for postgres_scanner are currently not run. All of them need a postgres server running. One test
#       uses a remote rds server but that's not something we want to run here.
if (NOT MINGW)
    duckdb_extension_load(postgres_scanner
            DONT_LINK
            GIT_URL https://github.com/duckdb/postgres_scanner
            GIT_TAG 8c3e9624ee1d32f317e18136056dfca9fb97ee67
            APPLY_PATCHES
            )
endif()

################# SPATIAL
if (NOT MINGW)
    duckdb_extension_load(spatial
            DONT_LINK LOAD_TESTS
            GIT_URL https://github.com/duckdb/duckdb_spatial.git
            GIT_TAG a86c504d60e0f4400564c0f2d633547f39feef2c
            INCLUDE_DIR spatial/include
            TEST_DIR test/sql
            APPLY_PATCHES
            )
endif()

################# SQLITE_SCANNER
# Static linking on windows does not properly work due to symbol collision
if (WIN32)
    set(STATIC_LINK_SQLITE "DONT_LINK")
else ()
    set(STATIC_LINK_SQLITE "")
endif()

duckdb_extension_load(sqlite_scanner
        ${STATIC_LINK_SQLITE} LOAD_TESTS
        GIT_URL https://github.com/duckdb/sqlite_scanner
        GIT_TAG bff9c0075bb8c3b5b483a87baa4ccfc34266023c
        )

################# SUBSTRAIT
if (NOT WIN32)
    duckdb_extension_load(substrait
            LOAD_TESTS DONT_LINK
            GIT_URL https://github.com/duckdb/substrait
            GIT_TAG 52ff1cab21e97053999bfeec83d1da976b94ef57
            APPLY_PATCHES
            )
endif()
