# test_reporter.py
# Unit tests for get_recommendation and the CSV export.
import csv
from reporter import get_recommendation, export_csv


def test_score_80_is_critical():
    assert get_recommendation({"score": 80}).startswith("Critical")


def test_score_79_is_high():
    assert get_recommendation({"score": 79}).startswith("High")


def test_score_50_is_high():
    assert get_recommendation({"score": 50}).startswith("High")


def test_outdated_low_score_suggests_update():
    assert get_recommendation({"score": 20, "is_outdated": True}).startswith("Consider updating")


def test_clean_package_is_low_risk():
    assert get_recommendation({"score": 0, "cves": []}) == "Package is up-to-date and low risk."


def test_csv_has_header_and_one_row_per_package(tmp_path):
    out = tmp_path / "report.csv"
    pkgs = [{"name": "django", "current_version": "2.2.0", "latest_version": "5.0",
             "is_outdated": True, "cves": [], "score": 20}]
    export_csv(pkgs, filename=str(out))
    rows = list(csv.reader(open(out)))
    assert rows[0][0] == "Package"
    assert rows[1][0] == "django"
    assert len(rows) == 2
