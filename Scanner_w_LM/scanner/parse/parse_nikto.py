#!/usr/bin/env python3

import csv
from pathlib import Path
from typing import List, Dict

def load_nikto_results(path: str | Path) -> List[Dict]:
    path = Path(path)
    findings: List[Dict] = []

    with path.open(newline='', encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            # Skip rows that are too short
            if len(row) < 7:
                continue

            host, ip, port, reference, method, uri, message = row

            findings.append({
                "scanner": "nikto",
                "title": "Nikto Issue",
                "severity": "info",  # Nikto doesn’t include severity levels
                "description": message,
                "url": f"http://{host}{uri}",
                "raw": row
            })

    return findings

if __name__ == "__main__":
    findings = load_nikto_results("out/nikto.csv")
    for f in findings:
        print(f"{f['url']} - {f['description']}")
