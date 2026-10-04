# parser.py
from packaging.requirements import Requirement, InvalidRequirement


def parse_requirements(filepath: str) -> list[dict]:
    packages = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()   # drop inline comments
            if not line or line.startswith("-"):    # skip blanks and pip options like -r
                continue
            try:
                req = Requirement(line)             # handles extras, markers, post/rc versions
            except InvalidRequirement:
                continue
            specs = list(req.specifier)
            if not specs:                           # unpinned package: no version to check
                continue
            pinned = [s for s in specs if s.operator in ("==", "===")]
            spec = pinned[0] if pinned else specs[0]
            packages.append({
                "name": req.name,
                "operator": spec.operator,
                "current_version": spec.version,
                "latest_version": None,
                "cves": [],
                "score": 0,
            })
    return packages
