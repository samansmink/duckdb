#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./invalidate-nightly-extension.sh <extension_name> <duckdb_version> (<nightly_commit>)"
    exit 1
fi

if [ -z "$3" ]; then
    BASE_NIGHTLY_DIR="$2"
else
    BASE_NIGHTLY_DIR="$1/$3/$2"
fi

# CONFIG
BUCKET=duckdb-extensions-nightly
CLOUDFLARE_HOST=nightly-extensions.duckdb.org
CLOUDFRONT_DISTRIBUTION_ID=E2QQFJRDJOBJQP

### List the files
## REAL_RUN is to be used to move non-Wasm extensions
DRY_RUN="aws s3 ls s3://$BUCKET/$BASE_NIGHTLY_DIR --recursive | grep $1.duckdb_extension.gz | awk '{print \"s3://$BUCKET/\" \$4}'"
DRY_RUN_WASM="aws s3 ls s3://$BUCKET/$BASE_NIGHTLY_DIR --recursive | grep $1.duckdb_extension.wasm | awk '{print \"s3://$BUCKET/\" \$4}'"

CLOUDFRONT_ORIGINS=`aws cloudfront get-distribution --id $CLOUDFRONT_DISTRIBUTION_ID --query 'Distribution.DistributionConfig.Origins.Items[*].DomainName' --output text`

if [ "$DUCKDB_DEPLOY_SCRIPT_MODE" != "for_real" ]; then
  echo "!!!!!!!!!!!!!"
  echo "!! DRY RUN !!"
  echo "!!!!!!!!!!!!!"
  echo ""
fi

echo "Invalidating caches for:"
eval "$DRY_RUN"
eval "$DRY_RUN_WASM"
echo ""


### INVALIDATE THE CLOUDFRONT CACHE

# Parse the dry run output
output=$(eval "$DRY_RUN" && eval "$DRY_RUN_WASM" && eval "$DRY_RUN_WASM_OLD_STYLE")
s3_paths=()
while IFS= read -r line; do
  path=$(echo "$line" | sed "s#s3://$BUCKET/##" | awk '{print "/" $1}')
  s3_paths+=("$path")
done <<< "$output"

echo "Invalidating CLOUDFRONT origin: $CLOUDFRONT_ORIGINS"
echo "> Total files: ${#s3_paths[@]}"
echo "> Domain: $CLOUDFRONT_ORIGINS"
if [ "$DUCKDB_DEPLOY_SCRIPT_MODE" == "for_real" ]; then
  for path in "${s3_paths[@]}"; do
    aws cloudfront create-invalidation --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" --paths "$path"
  done
else
  for path in "${s3_paths[@]}"; do
    echo "    $path"
  done
fi
echo ""

### INVALIDATE THE CLOUDFLARE CACHE
if [ ! -z "$CLOUDFLARE_CACHE_PURGE_TOKEN" ]; then
   if [ "$DUCKDB_DEPLOY_SCRIPT_MODE" == "for_real" ]; then
     echo "CLOUDFLARE INVALIDATION"
     echo "> Total files: ${#s3_paths[@]}"
     for path in "${s3_paths[@]}"; do
       curl  --request POST --url https://api.cloudflare.com/client/v4/zones/84f631c38b77d4631b561207f2477332/purge_cache --header 'Content-Type: application/json' --header "Authorization: Bearer $CLOUDFLARE_CACHE_PURGE_TOKEN" --data "{\"files\": [\"http://$CLOUDFLARE_HOST$path\"]}"
       echo ""
     done
   else
     echo "CLOUDFLARE INVALIDATION (DRY RUN)"
     echo "> Total files: ${#s3_paths[@]}"
     echo "> Domain: $CLOUDFLARE_HOST"
     echo "> Paths:"
     for path in "${s3_paths[@]}"; do
       echo "    http://$CLOUDFLARE_HOST$path"
     done
   fi
else
    echo "##########################################"
    echo "WARNING! CLOUDFLARE INVALIDATION DISABLED!"
    echo "##########################################"
fi
