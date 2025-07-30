import subprocess
from scanner.parse.parse_nuclei import load_nuclei_results
from scanner.parse.parse_nikto import load_nikto_results
# from scanner.parse.parse_zap import load_zap_results
from AI.ai_explainer import explain_with_ai
from pathlib import Path
import sys
import re
from collections import defaultdict

# --------------------- Input target ---------------------
if len(sys.argv) != 2:
    print("Usage: python3 main.py <target_url>")
    sys.exit(1)

target = sys.argv[1]
target_name = re.sub(r"\W+", "_", target.replace("https://", "").replace("http://", ""))

# Create output dir
Path("out").mkdir(parents=True, exist_ok=True)
Path("report").mkdir(parents=True, exist_ok=True)

# --------------------- Versioned filenames ---------------------
def get_versioned_filename(base, ext, folder):
    counter = 1
    while True:
        path = Path(folder) / f"{base}_{counter}.{ext}"
        if not path.exists():
            return str(path)
        counter += 1

nuclei_out = get_versioned_filename(f"nuclei_{target_name}", "jsonl", "out")
nikto_out = get_versioned_filename(f"nikto_{target_name}", "csv", "out")
report_out = get_versioned_filename(f"report_{target_name}", "md", "report")

# --------------------- Run scanners ---------------------
print(f"[+] Running scans on: {target}")

try:
    subprocess.run(["python3", "scanner/run/run_nuclei.py", target, nuclei_out], check=True)
except Exception as e:
    print(f"[!] Nuclei scan failed: {e}")

try:
    subprocess.run(["python3", "scanner/run/run_nikto.py", target, nikto_out], check=True)
except Exception as e:
    print(f"[!] Nikto scan failed: {e}")

# Optional ZAP
# try:
#     subprocess.run(["python3", "scanner/run/run_zap.py", target], check=True)
# except Exception as e:
#     print(f"[!] ZAP scan failed: {e}")

# --------------------- Parse results ---------------------
print("[+] Parsing results...")
results = []

try:
    results += load_nuclei_results(nuclei_out)
except Exception as e:
    print(f"[!] Failed to load Nuclei results: {e}")

try:
    results += load_nikto_results(nikto_out)
except Exception as e:
    print(f"[!] Failed to load Nikto results: {e}")

# try:
#     results += load_zap_results("out/zap.json")
# except Exception as e:
#     print(f"[!] Failed to load ZAP results: {e}")

#  Deduplication for report building
unique = {(f["title"], f["url"]): f for f in results}
results = list(unique.values())

#  Group by vulnerability title for report building
print("[+] Generating markdown report...")
grouped = defaultdict(list)
for f in results:
    grouped[f["title"]].append(f)

with open(report_out, "w", encoding="utf-8") as f:
    f.write(f"# Vulnerability Report for {target}\n\n")
    for title, group in grouped.items():
        f.write(f"## {title}\n")
        f.write(f"- Scanner(s): {', '.join(set(g['scanner'] for g in group))}\n")
        f.write(f"- Severity: **{group[0]['severity']}**\n")
        f.write(f"- Affected URLs:\n")
        for g in group:
            f.write(f"  - {g['url']}\n")
        try:
            explanation = explain_with_ai(title, group[0]["severity"], group[0]["description"])
        except Exception as e:
            explanation = f"(AI explanation failed: {e})"
        f.write(f"- AI Explanation:\n\n{explanation}\n\n")

print(f"[✓] Report saved to: {report_out}")
