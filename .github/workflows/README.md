# DuckDB Workflows
This directory contains all the workflows DuckDB. Due to limitations of Github Actions preventing creation of 
subdirectories, this directory can not be nested. For this reason, the number of workflows should remain relatively
limited, and we use a naming scheme to distinguish between reusable workflows and non-reusable ones:
- `_reusable_workflows.yml` are snake_cased and prefixed with an `_`. Resusable workflows can only be called by other workflows
and are not triggered directly by GitHub events
- `OtherWorkFlows.yml` are pascal cased. These are trigger by a GitHub event such as a push to a branch or a PR sync.
