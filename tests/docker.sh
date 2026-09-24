#!/bin/sh
# Run the test suite in a Debian container with the working tree as it is now.
#
#   sh tests/docker.sh
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$REPO":/repo:ro python:3.12-slim-bookworm sh -c '
apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y libxml2-utils >/dev/null 2>&1
cp -r /repo /tmp/sa && cd /tmp/sa && bash tests/run_tests.sh
'
