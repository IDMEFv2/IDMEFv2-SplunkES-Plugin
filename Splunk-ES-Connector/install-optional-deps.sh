#!/usr/bin/env bash
# install-optional-deps.sh — Install the optional libraries into bin/lib.
# Enables full IDMEFv2 JSON Schema validation. Run from the app folder or
# anywhere: bash install-optional-deps.sh
# Python override: PYTHON_BIN="/path/to/python3" bash install-optional-deps.sh

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${APP_DIR}/bin/lib"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PYTHON_CMD=("${PYTHON_BIN}")
elif [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
  PYTHON_CMD=("${SPLUNK_HOME}/bin/splunk" cmd python3)
else
  PYTHON_CMD=(python3)
fi

echo "Installing optional libraries into ${TARGET_DIR}"
rm -rf "${TARGET_DIR}"
"${PYTHON_CMD[@]}" -m pip install --no-compile --target "${TARGET_DIR}" \
  -r "${APP_DIR}/requirements-optional.txt"

echo "Done. Full IDMEFv2 schema validation is active from the next alert action run."
echo "Reinstall after every app upgrade: the upgrade replaces bin/lib."
