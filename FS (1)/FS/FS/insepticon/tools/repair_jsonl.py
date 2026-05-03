"""
Repair / scan JSONL files for malformed lines.
- For each input file, creates:
  - {file}.bak (backup)
  - {file}.fixed (contains valid JSON objects, one per line)
  - {file}.corrupt.log (contains lines that couldn't be parsed or salvaged)

Strategy:
- For each line try json.loads(line).
- If it fails, use json.JSONDecoder().raw_decode in a loop to attempt to parse multiple concatenated objects from the line.
- If the entire line can be consumed as objects, write them to the fixed file.
- Otherwise write the raw line to the corrupt log for manual inspection.

Run: python tools/repair_jsonl.py data/user_activity.jsonl data/logs.jsonl
"""

import os
import sys
import json
import shutil
from datetime import datetime


def process_file(path):
    print(f"Processing: {path}")
    if not os.path.exists(path):
        print(f"  Skipping — file not found: {path}")
        return {"path": path, "status": "missing"}

    bak = path + ".bak"
    fixed = path + ".fixed"
    corrupt_log = path + ".corrupt.log"

    # backup
    shutil.copy2(path, bak)
    print(f"  Backed up to: {bak}")

    decoder = json.JSONDecoder()
    total = 0
    parsed = 0
    salvaged = 0
    quarantined = 0

    with open(path, 'r', encoding='utf-8', errors='replace') as src, \
         open(fixed, 'w', encoding='utf-8') as out_fixed, \
         open(corrupt_log, 'w', encoding='utf-8') as out_corrupt:

        for lineno, raw_line in enumerate(src, start=1):
            total += 1
            line = raw_line.rstrip('\n')
            if not line.strip():
                continue

            # Remove BOM if present
            s = line.lstrip('\ufeff')

            # Try simple parse first
            try:
                obj = json.loads(s)
                out_fixed.write(json.dumps(obj, ensure_ascii=False) + '\n')
                parsed += 1
                continue
            except json.JSONDecodeError:
                pass

            # Try to parse multiple concatenated JSON objects via raw_decode
            idx = 0
            length = len(s)
            consumed_any = False
            success_full = True
            while idx < length:
                # skip whitespace
                while idx < length and s[idx].isspace():
                    idx += 1
                if idx >= length:
                    break
                try:
                    obj, end = decoder.raw_decode(s, idx)
                    consumed_any = True
                    out_fixed.write(json.dumps(obj, ensure_ascii=False) + '\n')
                    salvaged += 1
                    idx = end
                except json.JSONDecodeError:
                    success_full = False
                    break

            if success_full and consumed_any:
                # consumed the whole line (or trailing whitespace), considered salvaged
                continue

            # Couldn't salvage whole line — write to corrupt log with context
            out_corrupt.write(f"# LINE {lineno} — {datetime.utcnow().isoformat()}\n")
            out_corrupt.write(line + '\n\n')
            quarantined += 1

    print(f"  Totals: total={total}, parsed={parsed}, salvaged={salvaged}, quarantined={quarantined}")
    return {"path": path, "total": total, "parsed": parsed, "salvaged": salvaged, "quarantined": quarantined, "fixed": fixed, "corrupt_log": corrupt_log, "bak": bak}


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python tools/repair_jsonl.py <file1.jsonl> [file2.jsonl ...]")
        sys.exit(1)

    results = []
    for p in sys.argv[1:]:
        results.append(process_file(p))

    print('\nSummary:')
    for r in results:
        print(r)
