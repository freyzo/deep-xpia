"""Agreement between annotators, and between the scorer and the adjudicated labels.

Inputs (results/annotation/): items_v2.csv, key_v2.csv, labels_a.csv, labels_b.csv
(item_id, label, ...), and optionally adjudicated.csv. Writes agreement.md.

Run from the repo root:  python scripts/annotation_agreement.py
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from deep_xpia.bench.outcomes import SCORER_VERSION, OutcomeLabel, injected_hops_v2, score_run
from deep_xpia.bench.schema import BenchCase, RunResult

ROOT = Path(__file__).resolve().parents[1]
ANN = ROOT / "results/annotation"
LABELS = [label.value for label in OutcomeLabel]
KAPPA_MIN = 0.70


def cohen_kappa(a: list[str], b: list[str]) -> float:
    """Multi-class Cohen's kappa for two raters over the same items."""
    if len(a) != len(b) or not a:
        raise ValueError("need two equally long, non-empty label lists")
    n = len(a)
    observed = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


def per_label_precision_recall(truth: list[str], pred: list[str]) -> dict[str, tuple[int, float | None, float | None]]:
    out = {}
    for lab in LABELS:
        tp = sum(t == lab and p == lab for t, p in zip(truth, pred))
        n_pred, n_true = pred.count(lab), truth.count(lab)
        out[lab] = (n_true, tp / n_pred if n_pred else None, tp / n_true if n_true else None)
    return out


def _read(path: Path) -> dict[str, str]:
    with path.open(newline="") as f:
        rows = {r["item_id"]: r["label"].strip() for r in csv.DictReader(f)}
    bad = {k: v for k, v in rows.items() if v and v not in LABELS}
    if bad:
        raise SystemExit(f"{path.name}: unknown labels {sorted(set(bad.values()))}")
    return rows


def scorer_labels() -> dict[str, str]:
    with (ANN / "items_v2.csv").open(newline="") as f:
        items = list(csv.DictReader(f))
    with (ANN / "key_v2.csv").open(newline="") as f:
        key = {r["item_id"]: r["run_file"] for r in csv.DictReader(f)}
    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in
                               (ROOT / "deepxpiabench-v2.jsonl").read_text().splitlines() if ln.strip())}
    runs: dict[tuple[str, str], RunResult] = {}
    for fname in set(key.values()):
        for ln in (ROOT / "results/raw/v2-live-2026-06" / fname).read_text().splitlines():
            if ln.strip():
                r = RunResult.model_validate_json(ln)
                runs[(fname, r.case_id)] = r
    out = {}
    for it in items:
        case = cases[it["case_id"]]
        run = runs[(key[it["item_id"]], it["case_id"])]
        out[it["item_id"]] = score_run(case, run, injected_hops_v2(case)).per_hop[int(it["hop"])].value
    return out


def main() -> None:
    a, b = _read(ANN / "labels_a.csv"), _read(ANN / "labels_b.csv")
    ids = sorted(k for k in a if a[k] and b.get(k))
    kappa = cohen_kappa([a[i] for i in ids], [b[i] for i in ids])
    lines = [
        "# Annotation agreement (v2 sample)",
        "",
        f"Items labeled by both annotators: {len(ids)}",
        f"Cohen's kappa (multi-class): {kappa:.3f} (target >= {KAPPA_MIN}: {'met' if kappa >= KAPPA_MIN else 'NOT met'})",
        "",
    ]
    adj_path = ANN / "adjudicated.csv"
    if adj_path.exists():
        adj = _read(adj_path)
        sc = scorer_labels()
        both = sorted(i for i in adj if adj[i])
        truth, pred = [adj[i] for i in both], [sc[i] for i in both]
        lines += [
            f"## Scorer `{SCORER_VERSION}` vs adjudicated labels ({len(both)} items)",
            "",
            f"Accuracy: {sum(t == p for t, p in zip(truth, pred)) / len(both):.3f}; "
            f"Cohen's kappa: {cohen_kappa(truth, pred):.3f}",
            "",
            "| Label | adjudicated n | precision | recall |",
            "|---|---|---|---|",
        ]
        for lab, (n, prec, rec) in per_label_precision_recall(truth, pred).items():
            fmt = lambda x: "-" if x is None else f"{x:.2f}"  # noqa: E731
            lines.append(f"| {lab} | {n} | {fmt(prec)} | {fmt(rec)} |")
    (ANN / "agreement.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
