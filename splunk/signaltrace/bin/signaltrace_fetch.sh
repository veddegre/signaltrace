#!/bin/bash
# SignalTrace scripted input for Splunk
# Incrementally fetches new events from the SignalTrace JSON export endpoint
# and emits each as a single-line JSON event for Splunk to index.
#
# Setup instructions: https://github.com/veddegre/signaltrace/wiki/Splunk-Integration
#
# Configuration:
#   1. Set ENDPOINT to your SignalTrace base URL + /export/json
#   2. Set TOKEN to your EXPORT_API_TOKEN from config.local.php / .env
#   3. Set INDEX in inputs.conf (default: security)
#   4. Set disabled = false in inputs.conf to enable

set -uo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
ENDPOINT="https://yourdomain.example/export/json"
TOKEN="your-generated-token"

CURL="${CURL:-/usr/bin/curl}"
PYTHON="${PYTHON:-/usr/bin/python3}"

STATE_DIR="$SPLUNK_HOME/var/lib/signaltrace"
STATE_FILE="$STATE_DIR/last_id"
TIMESTAMP_FILE="$STATE_DIR/last_ms"
LOCKFILE="/tmp/signaltrace_fetch.lock"
TMPFILE="/tmp/signaltrace_fetch.$$.json"
ERRFILE="/tmp/signaltrace_fetch_err.$$"
NEWSTATE_ID="/tmp/signaltrace_lastid.$$"
NEWSTATE_MS="/tmp/signaltrace_lastms.$$"

cleanup() {
    rm -f "$TMPFILE" "$ERRFILE" "$NEWSTATE_ID" "$NEWSTATE_MS"
}
trap cleanup EXIT

# Prevent overlapping runs — if another instance is running, exit cleanly.
exec 9>"$LOCKFILE"
flock -n 9 || {
    echo "signaltrace_fetch: another instance is running, skipping." >&2
    exit 0
}

mkdir -p "$STATE_DIR"

# Initialise state files on first run.
[ -f "$STATE_FILE" ]    || echo "0"  > "$STATE_FILE"
[ -f "$TIMESTAMP_FILE" ] || echo "0" > "$TIMESTAMP_FILE"

LAST_ID=$(cat "$STATE_FILE")
LAST_MS=$(cat "$TIMESTAMP_FILE")

# Build the request URL. Pass ?from= if we have a previous timestamp so the
# server filters server-side, reducing payload on busy instances.
URL="$ENDPOINT"
if [ "$LAST_MS" -gt 0 ] 2>/dev/null; then
    URL="${ENDPOINT}?from=${LAST_MS}"
fi

# Prevent Splunk SSL environment variables from interfering with curl.
unset SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE

CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

"$CURL" -sS --fail \
    --cacert "$CA_BUNDLE" \
    --connect-timeout 15 \
    --max-time 60 \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/json" \
    "$URL" > "$TMPFILE" 2> "$ERRFILE"

CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
    echo "signaltrace_fetch: curl failed (exit ${CURL_EXIT})" >&2
    cat "$ERRFILE" >&2
    # Exit 0 so Splunk does not mark the input as permanently failed.
    # The next scheduled run will retry.
    exit 0
fi

if [ ! -s "$TMPFILE" ]; then
    echo "signaltrace_fetch: empty response — no events to index." >&2
    exit 0
fi

# Validate the response is JSON before passing to Python.
if ! "$PYTHON" -c "import json,sys; json.load(open(sys.argv[1]))" "$TMPFILE" 2>/dev/null; then
    echo "signaltrace_fetch: response is not valid JSON." >&2
    head -c 512 "$TMPFILE" >&2
    exit 0
fi

"$PYTHON" - "$TMPFILE" "$LAST_ID" "$NEWSTATE_ID" "$NEWSTATE_MS" << 'PY'
import json
import sys

json_file  = sys.argv[1]
last_id    = int(sys.argv[2])
state_id   = sys.argv[3]
state_ms   = sys.argv[4]

with open(json_file, "r", encoding="utf-8") as f:
    data = json.load(f)

if not isinstance(data, list):
    print("signaltrace_fetch: unexpected response format", file=sys.stderr)
    sys.exit(0)

max_id = last_id
max_ms = 0

for event in data:
    event_id = int(event.get("id", 0))
    if event_id > last_id:
        print(json.dumps(event, separators=(",", ":")))
        if event_id > max_id:
            max_id = event_id
        event_ms = int(event.get("clicked_at_unix_ms", 0))
        if event_ms > max_ms:
            max_ms = event_ms

with open(state_id, "w", encoding="utf-8") as f:
    f.write(str(max_id))

with open(state_ms, "w", encoding="utf-8") as f:
    f.write(str(max_ms) if max_ms > 0 else "0")
PY

PYTHON_EXIT=$?

if [ $PYTHON_EXIT -ne 0 ]; then
    echo "signaltrace_fetch: Python processing failed (exit ${PYTHON_EXIT})" >&2
    exit 0
fi

# Only advance state if Python produced new state files.
[ -s "$NEWSTATE_ID" ] && mv "$NEWSTATE_ID" "$STATE_FILE"
[ -s "$NEWSTATE_MS" ] && mv "$NEWSTATE_MS" "$TIMESTAMP_FILE"
