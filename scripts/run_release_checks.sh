#!/usr/bin/env bash
# Explicit finite checks on a controlled online test machine; not a runtime daemon.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
echo 'Release: checking build and syntax'
.venv/bin/python -m pip install --no-deps --no-build-isolation -e . > release-editable-install.log 2>&1
.venv/bin/python -m pip freeze --exclude-editable > requirements-lock.txt
bash -n scripts/compat_linux.sh scripts/prepare_offline.sh
.venv/bin/python -m compileall -q src tests scripts
echo 'Release: Ubuntu regression'
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q --junitxml=release-test-results.xml > release-test-output.log 2>&1
cat release-test-output.log
cp release-test-results.xml docs/release-test-results.xml
cp release-test-output.log docs/release-test-output.txt
echo 'Release: Fedora/Debian build dependency update and regression'
bash scripts/compat_linux.sh update
bash scripts/compat_linux.sh test
.venv/bin/python scripts/summarize_compat.py > release-compat-summary.log
cat release-compat-summary.log
echo 'Release: actual owned Lab/XML/PDF evidence'
.venv/bin/python scripts/validate_release.py --output docs/release-evidence > release-validation-output.log
cat release-validation-output.log
runtime=$(mktemp -d)
trap 'rm -rf "$runtime"' EXIT
.venv/bin/python -m secram --data-dir "$runtime" --doctor > docs/release-evidence/doctor.json
.venv/bin/python -m secram --data-dir "$runtime" --self-check > docs/release-evidence/self-check.json
QT_QPA_PLATFORM=offscreen .venv/bin/python -m secram --data-dir "$runtime" --smoke-test > release-gui-smoke.log 2>&1
echo 0 > docs/release-evidence/gui-exit-code.txt
.venv/bin/python -m secram --help > docs/cli-help.txt
.venv/bin/python -m pip wheel --no-deps --no-build-isolation . --wheel-dir build/wheels > release-wheel-build.log 2>&1
.venv/bin/python scripts/finalize_release_docs.py
echo 'RELEASE_CHECKS_COMPLETE'
