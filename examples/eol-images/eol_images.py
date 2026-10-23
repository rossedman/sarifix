#!/usr/bin/env python3
"""eol-images: flag Dockerfile base images that are past end of life.

A small in-house scanner used in the sarifix tutorials. It shows that any
script that can find a problem and write SARIF 2.1.0 plugs into sarifix
through config alone.

Usage: eol_images.py <dir> <out.sarif>
"""

import json
import re
import sys
from pathlib import Path

# image name -> (tag pattern, replacement advice). Dates are when upstream
# support ended.
EOL = {
    "node": (
        r"^(1[0-8])(\.|-|$)|^lts-buster",
        "Node.js 18 and older are end of life; use node:22 or newer.",
    ),
    "python": (
        r"^3\.[0-9](\.|-|$)",
        "Python 3.9 and older are end of life (3.9 ended October 2025); use python:3.12 or newer.",
    ),
    "nginx": (
        r"^1\.(1[0-9]|2[0-4])(\.|-|$)",
        "nginx 1.24 and older no longer get fixes; use nginx:stable.",
    ),
    "mcr.microsoft.com/dotnet/sdk": (
        r"^[1-7]\.",
        ".NET 7 and older are end of life; use 8.0 or newer.",
    ),
    "rust": (r"buster", "Debian buster images are end of life; use a bookworm tag."),
}

FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>[^\s:@]+)(?::(?P<tag>[^\s@]+))?",
    re.IGNORECASE,
)


def scan(root: Path) -> list[dict]:
    """Return one SARIF result per end-of-life FROM line under root."""
    results = []
    for path in sorted(root.rglob("Dockerfile*")):
        if ".git" in path.parts or not path.is_file():
            continue
        for number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            match = FROM.match(line)
            if not match:
                continue
            image, tag = match["image"], match["tag"] or "latest"
            rule = EOL.get(image)
            if rule and re.search(rule[0], tag):
                results.append(
                    {
                        "ruleId": "EOL_BASE_IMAGE",
                        "level": "warning",
                        "message": {"text": f"{image}:{tag} is end of life. {rule[1]}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": path.relative_to(root).as_posix()
                                    },
                                    "region": {"startLine": number},
                                }
                            }
                        ],
                    }
                )
    return results


def main() -> None:
    """Scan argv[1] and write SARIF to argv[2]."""
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "eol-images",
                        "rules": [
                            {
                                "id": "EOL_BASE_IMAGE",
                                "shortDescription": {
                                    "text": "Base image is end of life"
                                },
                                "help": {
                                    "text": "Move the FROM line to a supported tag of the same image."
                                },
                            }
                        ],
                    }
                },
                "results": scan(root),
            }
        ],
    }
    out.write_text(json.dumps(log, indent=2) + "\n")


if __name__ == "__main__":
    main()
