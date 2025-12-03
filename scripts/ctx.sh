#!/usr/bin/env bash
set -euo pipefail

OUT="_ai/agent-context-index.md"
DEPTH="${DEPTH:-2}"     # tree/find depth
LINES="${LINES:-300}"   # max grep lines
IGNORE_DIRS=(node_modules .git dist build .venv target __pycache__ .expo .next .pytest_cache _tmp)

mkdir -p "$(dirname "$OUT")"

# ---- Header ---------------------------------------------------------------
{
  echo "# Oord-Agent Context Index"
  echo
  echo "## Directory Tree (trimmed)"
} > "$OUT"

# ---- Directory tree (tree -> find fallback) ------------------------------
if command -v tree >/dev/null 2>&1; then
  IGNORE_PATTERN="$(IFS='|'; echo "${IGNORE_DIRS[*]}")"
  tree -I "$IGNORE_PATTERN" -L "$DEPTH" >> "$OUT" || true
else
  echo "(tree not found; using find)" >> "$OUT"
  IGNORE_PATTERN="$(IFS='|'; echo "${IGNORE_DIRS[*]}")"
  find . -maxdepth "$DEPTH" -mindepth 1 \
    | grep -Ev '^./('"$IGNORE_PATTERN"')(/|$)' \
    | sed 's|^\./||' >> "$OUT" || true
fi

# ---- Grep section --------------------------------------------------------
{
  echo
  echo "## Grep (gateway/portal/merkle/signature)"
} >> "$OUT"

if command -v rg >/dev/null 2>&1; then
  RG_ARGS=(--hidden -n)
  for d in "${IGNORE_DIRS[@]}"; do
    RG_ARGS+=(-g "!$d/**")
  done
  # NOTE: keep the pipeline on one line; do not move '| head ...' to a new line
  rg "${RG_ARGS[@]}" \
     -e '@router\.|FastAPI\(|Pydantic|Schema|type ' \
     -e 'Merkle|verify|sign|ed25519|sha256|reqwest|notify|Cargo\.toml' \
     | head -n "$LINES" >> "$OUT" || true
else
  echo "(ripgrep not found; skipping rg section)" >> "$OUT"
fi

# ---- Git log -------------------------------------------------------------
{
  echo
  echo "## Recent Commits"
} >> "$OUT"
git log -n 10 --pretty='- %h %s' >> "$OUT" || true

# ---- Timestamp -----------------------------------------------------------
{
  echo
  echo "## Timestamp"
  date -u +"Generated: %Y-%m-%d %H:%M:%SZ (UTC)"
} >> "$OUT"

echo "Wrote $OUT"
