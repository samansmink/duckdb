//===----------------------------------------------------------------------===//
//
//                         DuckDB
//
// sgx_stats.hpp
//
// Author: Sam Ansmink
//
//===----------------------------------------------------------------------===//

#pragma once

#include <time.h>
#include "stdio.h"

namespace duckdb {

#define SGX_STATS   "sgx_stats"

struct sgx_stats {
    unsigned int enclaves_created;
    unsigned int enclaves_released;
    unsigned long pages_added;
    unsigned long pageins;
    unsigned long pageouts;
    unsigned int enclave_pages;
    unsigned int va_pages;
    unsigned int free_pages;
    struct timespec readtime;
};

int sgx_stats_read(struct sgx_stats *stats)
{
    FILE *fp;

    if (!(fp = fopen(SGX_STATS, "ro"))) {
        fprintf(stderr, "failed to read %s\n", SGX_STATS);
        exit(-1);
    }

    int r = fscanf(fp, "%u %u %lu %lu %lu %u %u %u\n",
               &stats->enclaves_created, &stats->enclaves_released,
               &stats->pages_added, &stats->pageins, &stats->pageouts,
               &stats->enclave_pages, &stats->va_pages,
               &stats->free_pages);
    fclose(fp);
    if (r != 8) {
        fprintf(stderr, "expect to read %d entries from %s, got %d\n",
            8, SGX_STATS, r);
        return -1;
    }

    r = clock_gettime(CLOCK_MONOTONIC, &stats->readtime);
    if (r) {
        fprintf(stderr, "clock_gettime(3) returned %d, errno %d\n",
            r, errno);
        return r;
    }

    return 0;
}


} // namespace duckdb
