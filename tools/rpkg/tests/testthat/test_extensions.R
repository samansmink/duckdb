library("DBI")
library("testthat")

test_that("extensions can be loaded", {
  con <- dbConnect(duckdb::duckdb())
  on.exit(dbDisconnect(con, shutdown = TRUE))

  df0 <- data.frame(
    id = c(1, 2, 3),
    first_name = c("Amanda", "Albert", "Evelyn"),
    last_name = c("Jordan", "Freeman", "Morgan"),
    stringsAsFactors = FALSE
  )

  matches = list.files(pattern='*.duckdb_extension', recursive=FALSE, full.names=TRUE)
  matches <- c(matches, list.files(pattern=paste(extension_path, '/tmp/*/*.duckdb_extension', sep = ""), recursive=FALSE, full.names=TRUE))

  require_variable <- Sys.getenv("DUCKDB_R_TEST_EXTENSION_REQUIRED")

  if (require_variable == "1") {
    expect_true(length(matches) > 0, "DUCKDB_R_TEST_EXTENSION_REQUIRED was set, but no extensions were found")
  }

  for (extension in matches){
    query <- paste("LOAD '", extension, "';", sep = "")
    dbExecute(con, query)
    if (grepl("httpfs.duckdb_extension", extension, fixed = TRUE)) {
        res <- dbGetQuery(con, "SELECT id, first_name, last_name FROM PARQUET_SCAN('https://raw.githubusercontent.com/cwida/duckdb/master/data/parquet-testing/userdata1.parquet') LIMIT 3;")
        expect_equal(df0, res)
    }
  }
})