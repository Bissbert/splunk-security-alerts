#!/bin/sh
# Runs every check in docs/measurement.md inside a Linux container.
#
#   sh tools/linux-run.sh > media/captures/linux-run.txt
#
# The repository is mounted read-only and copied inside the container. No
# Splunk instance is started; everything here reads the checked-in files.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=python:3.12-slim-bookworm

docker pull -q "$IMAGE" >/dev/null
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$REPO":/repo:ro "$IMAGE" sh -c '
section() { printf "\n=== %s\n" "$*"; }
apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y libxml2-utils >/dev/null 2>&1
cp -r /repo /tmp/sa && cd /tmp/sa

section "environment"
uname -srm
python3 --version
bash --version | head -1
xmllint --version 2>&1 | head -1

section "python3 tools/measure_alerts.py"
python3 tools/measure_alerts.py

section "bash -n on every shell script"
for f in deployment/deploy.sh deployment/deploy_secure.sh scripts/install-hooks.sh scripts/package-splunk-app.sh tests/run_tests.sh; do
    bash -n "$f" && echo "ok  $f" || echo "FAIL $f"
done

section "compile security_alerts_app/bin/security_validator.py"
python3 -c "compile(open(\"security_alerts_app/bin/security_validator.py\").read(), \"security_validator.py\", \"exec\"); print(\"ok\")"

section "python3 tests/test_searches.py"
python3 tests/test_searches.py
echo "exit=$?"

section "python3 -m unittest test_validator test_app_files"
(cd tests && python3 -m unittest -v test_validator test_app_files 2>&1)
echo "exit=$?"

section "bash tests/run_tests.sh"
bash tests/run_tests.sh >/tmp/rt.log 2>&1
rc=$?
sed "s/\x1b\[[0-9;]*m//g" /tmp/rt.log
echo "exit=$rc"
'
