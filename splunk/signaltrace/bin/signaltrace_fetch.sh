#!/bin/bash
# SignalTrace scripted input
# Edit ENDPOINT and TOKEN before enabling the input in inputs.conf.
#
# Full setup instructions: https://github.com/yourusername/signaltrace/wiki/Splunk-Integration

set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
ENDPOINT="https://yourdomain.example/export/json"
TOKEN="your-generated-token"

CURL="/usr/bin/curl"
PYTHON="/usr/bin/python3"

STATE_DIR="$SPLUNK_HOME/var/lib/signaltrace"
STATE_FILE="$STATE_DIR/last_id"
LOCKFILE="/tmp/signaltrace_fetch.lock"

TMPFILE="/tmp/signaltrace_fetch.$$"
ERRFILE="/tmp/signaltrace_fetch_err.$$"
NEWSTATE="/tmp/signaltrace_lastid.$$"

cleanup() {
  rm -f "$TMPFILE" "$ERRFILE" "$NEWSTATE"
}
trap cleanup EXIT

# Prevent overlapping runs
exec 9>"$LOCKFILE"
flock -n 9 || exit 0

mkdir -p "$STATE_DIR"

# Initialize state file
if [ ! -f "$STATE_FILE" ]; then
  echo "0" > "$STATE_FILE"
fi

LAST_ID=$(cat "$STATE_FILE")

# Prevent Splunk SSL env vars from breaking curl
unset SSL_CERT_FILE
unset SSL_CERT_DIR
unset CURL_CA_BUNDLE

CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

"$CURL" -sS --fail \
  --cacert "$CA_BUNDLE" \
  --connect-timeout 15 \
  --max-time 60 \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Accept: application/json" \
  "$ENDPOINT" >"$TMPFILE" 2>"$ERRFILE" || {
    echo "signaltrace_fetch: curl failed" >&2
    cat "$ERRFILE" >&2
    exit 1
  }

if [ ! -s "$TMPFILE" ]; then
  echo "signaltrace_fetch: empty response body" >&2
  exit 1
fi

"$PYTHON" - "$TMPFILE" "$LAST_ID" "$NEWSTATE" <<'PY'
import json
import sys

json_file = sys.argv[1]
last_id = int(sys.argv[2])
state_out = sys.argv[3]

with open(json_file, "r", encoding="utf-8") as f:
    data = json.load(f)

max_id = last_id

for event in data:
    event_id = int(event.get("id", 0))
    if event_id > last_id:
        print(json.dumps(event))
        if event_id > max_id:
            max_id = event_id

with open(state_out, "w", encoding="utf-8") as f:
    f.write(str(max_id))
PY

mv "$NEWSTATE" "$STATE_FILE"
