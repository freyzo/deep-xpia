"""Wilson score intervals used for every reported proportion."""

from __future__ import annotations

import pytest

from deep_xpia.bench.metrics import wilson_ci


@pytest.mark.parametrize(
    "k,n,lo,hi",
    [
        (5, 10, 0.2366, 0.7634),
        (0, 10, 0.0, 0.2775),
        (10, 10, 0.7225, 1.0),
        (69, 100, 0.5937, 0.7722),  # hand-computed
    ],
)
def test_known_values(k: int, n: int, lo: float, hi: float) -> None:
    got = wilson_ci(k, n)
    assert got[0] == pytest.approx(lo, abs=1e-4)
    assert got[1] == pytest.approx(hi, abs=1e-4)


def test_empty_sample_is_uninformative() -> None:
    assert wilson_ci(0, 0) == (0.0, 1.0)


def test_interval_contains_point_estimate() -> None:
    for k in range(0, 26):
        lo, hi = wilson_ci(k, 25)
        assert lo <= k / 25 <= hi
