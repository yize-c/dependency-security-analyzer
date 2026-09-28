# reporter.py
import csv
import requests  

def fetch_cve_summary(cve_id: str):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return "Failed to fetch CVE data."

        data = r.json()
        return data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]

    except Exception:
        return "Error retrieving CVE information."


def get_recommendation(pkg: dict) -> str:
    if pkg["score"] >= 80:
        return "Critical risk: Update immediately or replace this package."

    if pkg["score"] >= 50:
        return "High risk: Upgrade to a secure version as soon as possible."

    if pkg.get("is_outdated"):
        return "Consider updating to stay secure."

    if pkg.get("cves"):
        return "Monitor vulnerabilities and apply patches if needed."

    return "Package is up-to-date and low risk."



def print_report(packages: list[dict]):
    RED, YELLOW, GREEN, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[0m"

    print("\n" + "="*70)
    print("           DEPENDENCY SECURITY ANALYSIS REPORT")
    print("="*70)
    
    print(f"\n{'Package':<12} {'Version':<10} {'Latest':<10} {'Status':<10} {'CVEs':<5} {'Risk'}")
    print("-"*70)

    for pkg in packages:
        color = RED if pkg["score"] >= 70 else YELLOW if pkg["score"] >= 30 else GREEN
        status = "OUTDATED" if pkg.get("is_outdated") else "OK"

        version = pkg.get("current_version") or "N/A"
        latest = pkg.get("latest_version") or "N/A"
        cve_count = len(pkg.get("cves", []))

        print(f"{pkg['name']:<12} {version:<10} {latest:<10} {status:<10} {cve_count:<5} {color}{pkg['score']}{RESET}")

    print("\n" + "="*70)
    print("DETAILS")
    print("="*70)

    for pkg in sorted(packages, key=lambda x: x["score"], reverse=True):
        color = RED if pkg["score"] >= 70 else YELLOW if pkg["score"] >= 30 else GREEN

        version = pkg.get("current_version") or "N/A"
        latest = pkg.get("latest_version") or "N/A"

        print(f"\n{color}{pkg['name'].upper()} (Score: {pkg['score']}){RESET}")
        print("-"*60)
        print(f"Version: {version} → {latest}")
        print(f"Status: {'OUTDATED' if pkg.get('is_outdated') else 'Current'}")
        print(f"Total CVEs: {len(pkg.get('cves', []))}")

        print("\n Top 5 Vulnerabilities:")
        for cve in pkg.get("cves", [])[:5]:

            if cve.get("cve_id") and cve.get("ghsa_id"):
                vuln_id = f"{cve['cve_id']} ({cve['ghsa_id']})"
            else:
                vuln_id = cve.get("cve_id") or cve.get("ghsa_id") or cve.get("id")

            print(f"  • {vuln_id} {cve['summary'][:60]}")

        unknowns = [c for c in pkg.get("cves", []) if c["severity"] == "UNKNOWN"]
        if unknowns:
            print(f"\n⚠ {len(unknowns)} vulnerabilities have UNKNOWN severity")

        recommendation = get_recommendation(pkg)
        print(f"\nRecommendation:\n{recommendation}")
        
    print("\n" + "="*70)

    total = len(packages)
    outdated = sum(1 for p in packages if p.get("is_outdated"))
    high_risk = sum(1 for p in packages if p["score"] >= 70)

    print("\nSUMMARY")
    print(f"Total packages: {total}")
    print(f"Outdated packages: {outdated}")
    print(f"High-risk packages: {high_risk}")

    print("="*70)

    user_input = input("\nDo you want to search for a specific CVE? (y/n): ").strip().lower()

    if user_input == "y":
        while True:
            cve_id = input("\nEnter CVE ID (or type 'exit'): ").strip()

            if cve_id.lower() == "exit":
                break

            if not cve_id.startswith("CVE-"):
                print("Invalid CVE format.")
                continue

            print("\nFetching CVE details...\n")
            summary = fetch_cve_summary(cve_id)
            print(f"{cve_id}: {summary}")

    print("\n" + "="*70 + "\n")



def export_csv(packages: list[dict], filename="report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Package", "Current Version", "Latest Version",
            "Outdated", "CVE Count", "Risk Score", "Recommendation"
        ])

        for pkg in packages:
            writer.writerow([
                pkg["name"],
                pkg.get("current_version") or "N/A",
                pkg.get("latest_version") or "N/A",
                pkg.get("is_outdated", False),
                len(pkg.get("cves", [])),
                pkg.get("score", 0),
                get_recommendation(pkg)
            ])
