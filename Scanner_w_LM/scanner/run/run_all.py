import subprocess

def run_all_scanners(target: str):
    subprocess.run(["python3", "scanner/run/run_nuclei.py", target, "out/nuclei.jsonl"])
    subprocess.run(["python3", "scanner/run/run_nikto.py",  target, "out/nikto.csv"])
    subprocess.run(["python3", "scanner/run/run_zap.py",    target, "out/zap.json"])

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: run_all.py <target_url>")
        sys.exit(1)
    run_all_scanners(sys.argv[1])
