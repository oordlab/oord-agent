#!/usr/bin/env bash
set -euo pipefail

# From gateway/tests → repo root is two levels up
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/_out"
IN="$ROOT/Final_Reports"
CFG="$ROOT/configs/lab.config.yaml"

echo "🧪 E2E Lab Demo starting..."
rm -rf "$OUT"
mkdir -p "$OUT" "$IN"

# 1) Fixtures (idempotent)
if ! ls "$IN"/*.pdf >/dev/null 2>&1; then
  printf "%s\n" "%PDF-1.4" "%\xE2\xE3\xCF\xD3" "1 0 obj" "<<>>" "endobj" "trailer" "<<>>" "%%EOF" > "$IN/a.pdf"
  printf "%s\n" "%PDF-1.4" "%\xE2\xE3\xCF\xD3" "1 0 obj" "<<>>" "endobj" "trailer" "<<>>" "%%EOF" > "$IN/b.pdf"
fi

# 2) Build bundle via gateway (Makefile is at repo root)
make -C "$ROOT" lab-demo

# 3) Find newest pack, verify it looks sane
PACK="$(ls -t "$OUT"/*.zip | head -n1)"
echo "Using pack: $PACK"
file "$PACK" | grep -qi "Zip archive data"
unzip -l "$PACK" | tee "$OUT/verify.txt"
if ! unzip -l "$PACK" | egrep -q "manifest\.json|session\.json"; then
  echo "❌ Pack missing expected JSONs"; exit 2
fi

# 4) Attestation
make -C "$ROOT" attest

# 5) Vault loader CSV (Veeva)
"$ROOT/.venv/bin/python" "$ROOT/utils/vault_loader.py" \
  --inputs-dir "$IN" \
  --attestation "$OUT/attestation.pdf" \
  --cfg "$CFG" \
  --out "$OUT/vault_loader.csv"

# 6) Summarize outputs
echo "Artifacts:" | tee -a "$OUT/verify.txt"
ls -lh "$OUT" | tee -a "$OUT/verify.txt"
echo "✅ E2E happy path completed" | tee -a "$OUT/verify.txt"
echo "Done."
