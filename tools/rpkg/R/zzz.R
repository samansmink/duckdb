.onLoad <- function(libname, pkgname) {
  s3_register("dbplyr::dbplyr_edition", "duckdb_connection")
  s3_register("dbplyr::db_connection_describe", "duckdb_connection")
  s3_register("dbplyr::sql_translation", "duckdb_connection")
  s3_register("dbplyr::dbplyr_fill0", "duckdb_connection")
  s3_register("dbplyr::sql_expr_matches", "duckdb_connection")
  s3_register("dbplyr::sql_escape_date", "duckdb_connection")
  s3_register("dbplyr::sql_escape_datetime", "duckdb_connection")
  s3_register("dplyr::tbl", "duckdb_connection")

  duckdb_env <- asNamespace("duckdb")
  dllinfo <- library.dynam(pkgname, pkgname, lib.loc=libname, local=FALSE)
  routines <- getDLLRegisteredRoutines(dllinfo)
  lapply(routines$.Call, function(symbol) {
    assign(symbol$name, symbol, envir=duckdb_env)
  })

  #Register namespace mimicking https://github.com/wch/r-source/blob/a7bc962f5ec2a5200b71ca2d744732cffc5eb1ac/src/library/base/R/namespace.R#L620
  current_dynlibs <- duckdb_env[[".__NAMESPACE__."]][["dynlibs"]]
  setNamespaceInfo(duckdb_env, "dynlibs", c(current_dynlibs, list("duckdb"))
  print(getNamespaceInfo(duckdb_env, "dynlibs"))

  nativeRoutines <- list()
  nativeRoutines[["duckdb"]] <- routines$.Call
  setNamespaceInfo(duckdb_env, "nativeRoutines", routines)

  print(getNamespaceInfo(duckdb_env, "nativeRoutines"))

  NULL
}

