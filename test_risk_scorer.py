# test_risk_scorer.py
# Unit tests for compute_risk_score: each CVSS band, the outdated bonus, and the 100 cap.
from risk_scorer import compute_risk_score, score_all


def test_clean_package_scores_zero():
    assert compute_risk_score({"is_outdated": False, "cves": []}) == 0


def test_outdated_only_adds_20():
    assert compute_risk_score({"is_outdated": True, "cves": []}) == 20


# Boundary values: exactly on each threshold, and just below it
def test_cvss_9_0_is_critical_band():
    assert compute_risk_score({"cves": [{"cvss_score": 9.0}]}) == 50


def test_cvss_8_9_is_high_band():
    assert compute_risk_score({"cves": [{"cvss_score": 8.9}]}) == 30


def test_cvss_7_0_is_high_band():
    assert compute_risk_score({"cves": [{"cvss_score": 7.0}]}) == 30


def test_cvss_4_0_is_medium_band():
    assert compute_risk_score({"cves": [{"cvss_score": 4.0}]}) == 15


def test_cvss_3_9_is_low_band():
    assert compute_risk_score({"cves": [{"cvss_score": 3.9}]}) == 5


def test_score_never_exceeds_100():
    pkg = {"is_outdated": True, "cves": [{"cvss_score": 9.8}] * 5}
    assert compute_risk_score(pkg) == 100


def test_missing_keys_do_not_crash():
    assert compute_risk_score({}) == 0


def test_score_all_fills_every_package():
    pkgs = [{"cves": []}, {"is_outdated": True, "cves": []}]
    result = score_all(pkgs)
    assert [p["score"] for p in result] == [0, 20]
