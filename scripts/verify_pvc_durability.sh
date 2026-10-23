#!/usr/bin/env bash
# verify_pvc_durability.sh - Verificación operacional de durabilidad de un PVC RWO.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: python3 no está instalado en el sistema." >&2
  exit 1
fi

"$PYTHON_BIN" "${SCRIPT_DIR}/verify_pvc_durability.py" "$@"
