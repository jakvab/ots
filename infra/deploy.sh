#!/usr/bin/env bash
# ============================================================
# ots.jakvab.se — deploy static app to S3 + CloudFront
# Usage:
#   BUCKET=ots-jakvab-<ACCOUNT_ID> DISTRIBUTION_ID=E123ABC ./infra/deploy.sh
# ============================================================
set -euo pipefail

BUCKET="${BUCKET:?set BUCKET=your-s3-bucket-name}"
DISTRIBUTION_ID="${DISTRIBUTION_ID:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # the ots/ directory

echo "→ Syncing assets (long cache) ..."
aws s3 sync "$ROOT" "s3://$BUCKET" \
  --exclude ".*" \
  --exclude "infra/*" \
  --exclude "*.md" \
  --exclude "*.sh" \
  --exclude "*.html" \
  --cache-control "public,max-age=31536000,immutable" \
  --delete

echo "→ Uploading HTML pages (no cache) ..."
for page in "$ROOT"/*.html; do
  aws s3 cp "$page" "s3://$BUCKET/$(basename "$page")" \
    --cache-control "no-cache,must-revalidate" \
    --content-type "text/html"
done

if [[ -n "$DISTRIBUTION_ID" ]]; then
  echo "→ Invalidating CloudFront ($DISTRIBUTION_ID) ..."
  aws cloudfront create-invalidation --distribution-id "$DISTRIBUTION_ID" --paths "/*" >/dev/null
fi

echo "✓ Deployed."
