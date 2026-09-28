# parser.py
import re

def parse_requirements(filepath: str) -> list[dict]:
    packages = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # name may contain dots (zope.interface); optional extras like [security] are skipped
            match = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([><=!~]+)\s*([\d\.]+)", line)
            if match:
                packages.append({
                    "name": match.group(1),
                    "operator": match.group(2),
                    "current_version": match.group(3),
                    "latest_version": None,  
                    "cves": [],             
                    "score": 0              
                })
    return packages