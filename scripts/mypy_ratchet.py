"""mypy ratchet: per-file strict error counts may only go down.

    python scripts/mypy_ratchet.py            # check against mypy-baseline.json
    python scripts/mypy_ratchet.py --update   # record lower counts after fixing errors

Config is [tool.mypy] in pyproject.toml (strict). A file whose count rises,
or a new file with errors, fails the check.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "mypy-baseline.json"


def current_counts() -> Counter[str]:
    out = subprocess.run(
        [sys.executable, "-m", "mypy", "src"], cwd=ROOT, capture_output=True, text=True
    ).stdout
    return Counter(m.group(1) for m in re.finditer(r"^(src/[^:]+):\d+: error:", out, re.M))


def main() -> int:
    counts = current_counts()
    if "--update" in sys.argv:
        old = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
        if any(counts[f] > old.get(f, 0) for f in counts) and old:
            print("refusing to raise the baseline; fix the new errors instead")
            return 1
        BASELINE.write_text(json.dumps(dict(sorted(counts.items())), indent=2) + "\n")
        print(f"baseline: {sum(counts.values())} errors in {len(counts)} files")
        return 0
    baseline = json.loads(BASELINE.read_text())
    worse = {f: (baseline.get(f, 0), n) for f, n in counts.items() if n > baseline.get(f, 0)}
    better = {f: (n, counts.get(f, 0)) for f, n in baseline.items() if counts.get(f, 0) < n}
    for f, (was, now) in sorted(worse.items()):
        print(f"MORE mypy errors: {f}: {was} -> {now}")
    for f, (was, now) in sorted(better.items()):
        print(f"fewer mypy errors: {f}: {was} -> {now} (run --update to lock in)")
    print(f"total: {sum(counts.values())} (baseline {sum(baseline.values())})")
    return 1 if worse else 0


if __name__ == "__main__":
    sys.exit(main())
