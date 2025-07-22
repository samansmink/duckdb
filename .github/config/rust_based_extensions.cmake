#
# This is the extension configuration for extensions that require rust to build. This needs some extra setup in CI
# but also takes up a bit more disk space, which is why we run them in a separate build
#
# to build duckdb with this configuration run:
#   EXTENSION_CONFIGS=.github/config/rust-based-extensions.cmake make
#

################## DELTA
duckdb_extension_load(delta
        GIT_URL https://github.com/samansmink/duckdb_delta
        GIT_TAG f02b963271c6c867de8ac2901b5ed4cc67101304
        SUBMODULES extension-ci-tools
)
