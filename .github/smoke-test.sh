#!/usr/bin/env bash
# Check that an image is what the Containerfile promises: non-root, a single
# static binary, and working under a locked-down runtime configuration.
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}

user=$(docker inspect --format '{{.Config.User}}' "$image")
if [[ $user != 65534:65534 ]]; then
    echo "image runs as '$user', expected 65534:65534" >&2
    exit 1
fi

# The image must contain the exporter and nothing else.
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null' EXIT
files=$(docker export "$cid" | tar -t | grep -vE '^(dev|etc|proc|sys)(/|$)|^\.dockerenv$' || true)
if [[ $files != printer_exporter ]]; then
    echo "unexpected files in image:" >&2
    echo "$files" >&2
    exit 1
fi

# Nothing answers SNMP on localhost, so a correct exporter reports the
# printer as down. A dynamically linked binary would fail to start in scratch.
out=$(docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --network=none "$image" --once --timeout 0.5)
echo "$out"
grep -qx 'printer_up{target="127.0.0.1"} 0' <<<"$out"

# Server mode: the listener comes up and the image's own health probe passes.
docker rm -f "$cid" >/dev/null
cid=$(docker run -d --read-only --cap-drop=ALL --security-opt=no-new-privileges "$image")
sleep 2
docker exec "$cid" /printer_exporter --healthcheck
echo "healthcheck passed"
