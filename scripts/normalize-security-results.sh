#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-downloaded-artifacts}"
TARGET_DIR="${2:-security-results}"

mkdir -p "${TARGET_DIR}"

echo "[normalize] source=${SOURCE_DIR}"
echo "[normalize] target=${TARGET_DIR}"

if [ ! -d "${SOURCE_DIR}" ]; then
  echo "[normalize] ERROR: Source directory not found: ${SOURCE_DIR}"
  exit 1
fi

# Canonical JSON outputs expected by ia-triage.py
required=(
  "trufflehog-results.json"
  "semgrep-results.json"
  "snyk-results.json"
  "trivy-results.json"
  "zap-results.json"
)

fallback_content_for() {
  case "$1" in
    trufflehog-results.json) printf '%s\n' '[]' ;;
    semgrep-results.json) printf '%s\n' '{"results": []}' ;;
    snyk-results.json) printf '%s\n' '{"vulnerabilities": []}' ;;
    trivy-results.json) printf '%s\n' '{"Results": []}' ;;
    zap-results.json) printf '%s\n' '{"site": []}' ;;
    *) printf '%s\n' '{}' ;;
  esac
}

# Copy first match for each required file to avoid accidental overwrite.
for file in "${required[@]}"; do
  mapfile -t matches < <(find "${SOURCE_DIR}" -type f -name "${file}" | sort)

  if [ "${#matches[@]}" -eq 0 ]; then
    echo "[normalize] WARN: Not found -> ${file}"
    fallback_content_for "${file}" > "${TARGET_DIR}/${file}"
    echo "[normalize] WARN: Fallback created -> ${TARGET_DIR}/${file}"
    continue
  fi

  if [ "${#matches[@]}" -gt 1 ]; then
    echo "[normalize] WARN: Multiple matches for ${file}:"
    printf '  - %s\n' "${matches[@]}"
    echo "[normalize] INFO: Using first match: ${matches[0]}"
  fi

  cp "${matches[0]}" "${TARGET_DIR}/${file}"
  echo "[normalize] OK: ${file}"
done

echo "[normalize] Final files in ${TARGET_DIR}:"
ls -la "${TARGET_DIR}" || true
