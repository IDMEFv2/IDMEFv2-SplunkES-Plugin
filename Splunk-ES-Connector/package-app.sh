#!/usr/bin/env bash
# package-app.sh — Build a Splunk-installable .tar.gz package for the app.
# Usage: bash package-app.sh [output_dir]
# Output: <output_dir>/Splunk-ES-Connector-<version>.tar.gz

set -euo pipefail

APP_NAME="Splunk-ES-Connector"
VERSION="1.0.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}"
PARENT_DIR="$(dirname "${APP_DIR}")"

OUTPUT_DIR="${1:-${PARENT_DIR}}"
ARCHIVE_NAME="${APP_NAME}-${VERSION}.tar.gz"
OUTPUT_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"

mkdir -p "${OUTPUT_DIR}"

echo "Packaging ${APP_NAME} v${VERSION}..."
echo "App directory: ${APP_DIR}"
echo "Output path: ${OUTPUT_PATH}"

cd "${PARENT_DIR}"

tar -czf "${OUTPUT_PATH}" \
  --exclude="${APP_NAME}/local/*" \
  --exclude="${APP_NAME}/__pycache__" \
  --exclude="${APP_NAME}/bin/__pycache__" \
  --exclude="${APP_NAME}/appserver/__pycache__" \
  --exclude="${APP_NAME}/default/__pycache__" \
  --exclude="${APP_NAME}/metadata/__pycache__" \
  --exclude="${APP_NAME}/lookups/__pycache__" \
  --exclude="${APP_NAME}/*.pyc" \
  --exclude="${APP_NAME}/bin/*.pyc" \
  --exclude="${APP_NAME}/.git" \
  --exclude="${APP_NAME}/.gitignore" \
  --exclude="${APP_NAME}/*.tar.gz" \
  "${APP_NAME}/"

echo "Package created: ${OUTPUT_PATH}"