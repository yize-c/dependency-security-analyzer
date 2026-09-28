# risk_scorer.py

def compute_risk_score(pkg: dict) -> float:
    score = 0.0
    
    if pkg.get("is_outdated"):
        score += 20

    for cve in pkg.get("cves", []):
        cvss = cve.get("cvss_score", 0)
        if cvss >= 9.0:
            score += 50
        elif cvss >= 7.0:
            score += 30
        elif cvss >= 4.0:
            score += 15
        else:
            score += 5
    
    return min(score, 100) 

def score_all(packages: list[dict]) -> list[dict]:
    for pkg in packages:
        pkg["score"] = compute_risk_score(pkg)
    return packages