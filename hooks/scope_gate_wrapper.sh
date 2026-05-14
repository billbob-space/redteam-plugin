#!/usr/bin/env bash
# Wrapper qui invoque scope_gate.py avec le Python du venv local pour avoir pyyaml.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE"
while [ "$ROOT" != "/" ]; do
  if [ -x "$ROOT/.tools/venv/bin/python" ]; then
    exec "$ROOT/.tools/venv/bin/python" "$HERE/scope_gate.py" "$@"
  fi
  ROOT="$(dirname "$ROOT")"
done
exec python3 "$HERE/scope_gate.py" "$@"
