#!/usr/bin/env bash
# Wrapper qui invoque post_tool_log.py avec le Python du venv local pour avoir pyyaml.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE"
while [ "$ROOT" != "/" ]; do
  if [ -x "$ROOT/.tools/venv/bin/python" ]; then
    exec "$ROOT/.tools/venv/bin/python" "$HERE/post_tool_log.py" "$@"
  fi
  ROOT="$(dirname "$ROOT")"
done
exec python3 "$HERE/post_tool_log.py" "$@"
