import pytest

from app.shared.models import Finding, ModuleResult
from app.shared.xai_engine import aggregate, render_finding, tier_for


@pytest.mark.parametrize(
    "score,tier",
    [(0, "Safe"), (19, "Safe"), (20, "Low"), (39, "Low"), (40, "Medium"), (59, "Medium"),
     (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")],
)
def test_tier_boundaries(score, tier):
    assert tier_for(score) == tier


def test_single_module_score_passes_through():
    r = aggregate([ModuleResult("phishing", [Finding("ip_host", 30, {"host": "1.2.3.4"})])])
    assert r.score == 30 and r.tier == "Low" and r.decision == "allow"
    assert "1.2.3.4" in r.summary


def test_peak_floor_prevents_dilution():
    hot = ModuleResult("ato", [Finding("failed_burst", 60, {"failed": 30, "window_min": 5})])
    cold = ModuleResult("phishing", [])
    assert aggregate([hot, cold]).score >= 51


def test_score_is_capped_at_100():
    big = ModuleResult("ato", [Finding("failed_burst", 90), Finding("impossible_travel", 90)])
    assert aggregate([big]).score == 100


def test_unknown_code_and_missing_params_do_not_crash():
    assert "mystery" in render_finding("mystery", {})
    assert "?" in render_finding("ip_host", {})


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        aggregate([])
