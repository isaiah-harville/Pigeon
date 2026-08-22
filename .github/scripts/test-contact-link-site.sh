#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

aasa="site/.well-known/apple-app-site-association"
nginx="site/deploy/nginx/default.conf"

jq -e '
  .applinks.details == [{
    appIDs: ["PUMV3ZMP9G.com.isaiah-harville.Pigeon"],
    components: [{"/": "/contact", comment: "Pigeon contact links"}]
  }]
' "$aasa" >/dev/null

grep -F 'location = /.well-known/apple-app-site-association' "$nginx" >/dev/null
grep -F 'default_type application/json;' "$nginx" >/dev/null
grep -F 'location = /contact' "$nginx" >/dev/null
grep -F 'access_log off;' "$nginx" >/dev/null
grep -F 'return 302 https://apps.apple.com/app/id6780532820#app-store;' "$nginx" >/dev/null
grep -F 'COPY .well-known /usr/share/nginx/html/.well-known' site/deploy/Dockerfile >/dev/null

echo "Contact universal-link site configuration is valid."
