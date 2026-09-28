# version_checker.py
import requests
from packaging import version  

def get_latest_version(package_name: str) -> str | None:
    url = f"https://pypi.org/pypi/{package_name}/json"
    resp = requests.get(url, timeout=5)
    if resp.status_code == 200:
        return resp.json()["info"]["version"]
    return None

def check_versions(packages: list[dict]) -> list[dict]:
    for pkg in packages:
        latest = get_latest_version(pkg["name"])
        pkg["latest_version"] = latest
        if latest and pkg.get("current_version"):
            pkg["is_outdated"] = version.parse(pkg["current_version"]) < version.parse(latest)
        else:
            pkg["is_outdated"] = False
    return packages