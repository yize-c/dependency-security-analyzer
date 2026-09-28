# test_cve_lookup.py
# Unit tests for query_osv and classify_cvss.
# The OSV API is replaced with a fake response (monkeypatch), so tests run offline and always give the same result.
import requests
import cve_lookup
from cve_lookup import classify_cvss, query_osv, parse_cvss_score


class FakeResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


def fake_post(status_code, data):
    return lambda *args, **kwargs: FakeResponse(status_code, data)


def test_classify_cvss_boundaries():
    assert classify_cvss(9.0) == "CRITICAL"
    assert classify_cvss(7.0) == "HIGH"
    assert classify_cvss(6.9) == "MEDIUM"
    assert classify_cvss(4.0) == "MEDIUM"
    assert classify_cvss(3.9) == "LOW"


def test_api_error_returns_empty_list(monkeypatch):
    monkeypatch.setattr(cve_lookup.requests, "post", fake_post(500, {}))
    assert query_osv("django", "2.2.0") == []


def test_network_failure_returns_empty_list(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.ConnectionError("no network")
    monkeypatch.setattr(cve_lookup.requests, "post", boom)
    assert query_osv("django", "2.2.0") == []


def test_extracts_cve_and_ghsa_ids(monkeypatch):
    data = {"vulns": [{"id": "GHSA-xxxx", "aliases": ["CVE-2021-1234"], "summary": "test"}]}
    monkeypatch.setattr(cve_lookup.requests, "post", fake_post(200, data))
    v = query_osv("django", "2.2.0")[0]
    assert v["cve_id"] == "CVE-2021-1234"
    assert v["ghsa_id"] == "GHSA-xxxx"


# Real OSV responses give CVSS as a vector string, not a number, for example:
# {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}  (= 9.8 CRITICAL)
# Regression test: this used to fail because float() on the vector string made every CVE 0.0 / LOW.
def test_real_osv_vector_string_is_scored(monkeypatch):
    data = {"vulns": [{
        "id": "GHSA-test",
        "aliases": ["CVE-2019-0000"],
        "summary": "critical bug",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }]}
    monkeypatch.setattr(cve_lookup.requests, "post", fake_post(200, data))
    v = query_osv("django", "2.2.0")[0]
    assert v["severity"] == "CRITICAL"


def test_parse_cvss_score_vector_and_number():
    assert parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert parse_cvss_score("7.5") == 7.5


def test_parse_cvss_score_garbage_is_zero():
    assert parse_cvss_score("not-a-score") == 0.0
    assert parse_cvss_score(None) == 0.0
