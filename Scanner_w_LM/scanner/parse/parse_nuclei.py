import json
from pathlib import Path
from typing import List, Dict

def load_nuclei_results(path: str | Path) -> List[Dict]:
    findings = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            data = json.loads(line)
            info = data.get("info", {})
            findings.append({
                "scanner": "nuclei",
                "title": info.get("name", "Unnamed finding"),
                "severity": str(info.get("severity", "info")).lower(),
                "description": info.get("description", ""),
                "url": data.get("matched-at", ""),
                "raw": data
            })
    return findings
if __name__ == "__main__":
    findings = load_nuclei_results("out/nuclei.jsonl")
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['title']} → {f['url']}")
