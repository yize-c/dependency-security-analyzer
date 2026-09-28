# test_parser.py
# Unit tests for parse_requirements, using a temporary requirements.txt for each case.
from parser import parse_requirements


def write_req(tmp_path, text):
    f = tmp_path / "requirements.txt"
    f.write_text(text)
    return str(f)


def test_parses_name_operator_version(tmp_path):
    pkgs = parse_requirements(write_req(tmp_path, "django==2.2.0\n"))
    assert len(pkgs) == 1
    assert pkgs[0]["name"] == "django"
    assert pkgs[0]["operator"] == "=="
    assert pkgs[0]["current_version"] == "2.2.0"


def test_skips_blank_lines_and_comments(tmp_path):
    text = "# a comment\n\nflask==0.12\n"
    pkgs = parse_requirements(write_req(tmp_path, text))
    assert [p["name"] for p in pkgs] == ["flask"]


def test_handles_spaces_and_other_operators(tmp_path):
    pkgs = parse_requirements(write_req(tmp_path, "requests >= 2.18.0\n"))
    assert pkgs[0]["operator"] == ">="
    assert pkgs[0]["current_version"] == "2.18.0"


def test_new_package_starts_with_empty_results(tmp_path):
    pkg = parse_requirements(write_req(tmp_path, "numpy==1.18.0\n"))[0]
    assert pkg["cves"] == [] and pkg["score"] == 0 and pkg["latest_version"] is None


# Regression tests: these edge cases used to be skipped by the parser.
def test_package_name_with_dot(tmp_path):
    pkgs = parse_requirements(write_req(tmp_path, "zope.interface==5.4.0\n"))
    assert [p["name"] for p in pkgs] == ["zope.interface"]


def test_package_with_extras(tmp_path):
    pkgs = parse_requirements(write_req(tmp_path, "requests[security]==2.18.0\n"))
    assert [p["name"] for p in pkgs] == ["requests"]
