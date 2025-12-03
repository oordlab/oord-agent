#!/usr/bin/env bash
set -euo pipefail
set -x
trap 'echo "FAILED at line $LINENO"; exit 1' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$ROOT/_out" "$ROOT/tests/tmp"

python3 -c "import openpyxl,sys; print(openpyxl.__version__)"

printf "%s\n" "record_id,document_name,file_path,classification,version" \
"REC-001,Report A,Final_Reports/a.pdf,Lab Report,1.0" \
"REC-002,Report B,Final_Reports/b.pdf,Lab Report,1.0" > "$ROOT/tests/tmp/a.csv"

printf "%s\n" "version,classification,file_path,document_name,record_id" \
"1.0,Lab Report,Final_Reports/a.pdf,Report A,REC-001" \
"1.0,Lab Report,Final_Reports/b.pdf,Report B,REC-002" > "$ROOT/tests/tmp/b.csv"

python3 "$ROOT/utils/canonicalizer/csv_canonicalizer.py" --input "$ROOT/tests/tmp/a.csv" --out "$ROOT/_out/a_canon.csv" > "$ROOT/_out/a.sha"
python3 "$ROOT/utils/canonicalizer/csv_canonicalizer.py" --input "$ROOT/tests/tmp/b.csv" --out "$ROOT/_out/b_canon.csv" > "$ROOT/_out/b.sha"
diff -q "$ROOT/_out/a_canon.csv" "$ROOT/_out/b_canon.csv" >/dev/null || true
test "$(cat "$ROOT/_out/a.sha")" = "$(cat "$ROOT/_out/b.sha")"

ROOT="$ROOT" python3 - <<'PY'
import os, random, openpyxl
root = os.environ["ROOT"]
os.makedirs(f"{root}/tests/tmp", exist_ok=True)
wb = openpyxl.Workbook(); wb.remove(wb.active)
hdr = ["Record_ID","Document_Name","File_Path","Classification","Version"]
rows = [["REC-001","Report A","Final_Reports/a.pdf","Lab Report","1.0"],
        ["REC-002","Report B","Final_Reports/b.pdf","Lab Report","1.0"]]
for name in ["IQ","OQ"]:
    ws = wb.create_sheet(title=name)
    h = hdr[:]; random.shuffle(h); ws.append(h)
    idx = {v.lower(): i for i, v in enumerate(hdr)}
    for r in rows: ws.append([r[idx[x.lower()]] for x in h])
wb.save(f"{root}/tests/tmp/iqoq_v1.xlsx")
wb2 = openpyxl.load_workbook(f"{root}/tests/tmp/iqoq_v1.xlsx")
for ws in wb2.worksheets[::-1]:
    wb2.remove(ws); wb2._sheets.insert(0, ws)
wb2.save(f"{root}/tests/tmp/iqoq_v2.xlsx")
PY

python3 "$ROOT/utils/canonicalizer/xlsx_canonicalizer.py" --input "$ROOT/tests/tmp/iqoq_v1.xlsx" --out "$ROOT/_out/x1.xlsx" > "$ROOT/_out/x1.sha"
python3 "$ROOT/utils/canonicalizer/xlsx_canonicalizer.py" --input "$ROOT/tests/tmp/iqoq_v2.xlsx" --out "$ROOT/_out/x2.xlsx" > "$ROOT/_out/x2.sha"
x1="$(cat "$ROOT/_out/x1.sha")"
x2="$(cat "$ROOT/_out/x2.sha")"

if [ "$x1" != "$x2" ]; then
  echo "XLSX canonicalization mismatch"
  echo "x1.sha=$x1"
  echo "x2.sha=$x2"
  echo
  echo "x1.xlsx contents:"
  python -m zipfile -l "$ROOT/_out/x1.xlsx" || true
  echo
  echo "x2.xlsx contents:"
  python -m zipfile -l "$ROOT/_out/x2.xlsx" || true
  echo
  echo "Diff of unzipped XML (first 200 lines):"
  rm -rf "$ROOT/_out/x1_unzip" "$ROOT/_out/x2_unzip"
  unzip -q "$ROOT/_out/x1.xlsx" -d "$ROOT/_out/x1_unzip"
  unzip -q "$ROOT/_out/x2.xlsx" -d "$ROOT/_out/x2_unzip"
  diff -ru "$ROOT/_out/x1_unzip" "$ROOT/_out/x2_unzip" | head -200 || true
  exit 1
fi

echo "OK"
