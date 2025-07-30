import json
from pathlib import Path
from typing import List, Dict

def load_zap_results(path: str | Path) -> List[Dict]:
    findings = []
    with open(path, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskcode", "0")
            severity = {
                "0": "info",
                "1": "low",
                "2": "medium",
                "3": "high"
            }.get(risk, "info")

            findings.append({
                "scanner": "zap",
                "title": alert.get("alert", "ZAP Issue"),
                "severity": severity,
                "description": alert.get("desc", ""),
                "url": alert.get("uri") or site.get("@name", ""),
                "raw": alert
            })
    return findings
