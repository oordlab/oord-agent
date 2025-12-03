#!/usr/bin/env bash
set -euo pipefail
echo "→ Running lab-demo smoke test…"
export OORD_CORE_STUB=1
make lab-demo
ZIP="$(ls -t _out/*.zip 2>/dev/null | head -n1 || true)"
[[ -n "$ZIP" ]] || { echo "❌ No ZIP produced"; exit 1; }
[[ -f _out/vault_loader.csv ]] || { echo "❌ Missing _out/vault_loader.csv"; exit 1; }
LINES="$(wc -l < _out/vault_loader.csv | tr -d ' ')"
[[ "$LINES" -ge 2 ]] || { echo "❌ CSV has no data rows"; exit 1; }
echo "✅ OK — ZIP: $ZIP; CSV lines: $LINES"
