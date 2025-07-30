import sys
import subprocess
from pathlib import Path

def run_zap(target: str, output: str):
    Path("out").mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{Path.cwd() / 'out'}:/zap/wrk",
        "-v", f"{Path.cwd() / 'scanner/config'}:/zap/config",
        "owasp/zap2docker-stable", "zap-full-scan.py",
        "-c", "/zap/config/zap.yaml"
    ]
    subprocess.run(cmd, check=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: run_zap.py <target_url> <output_file>")
        sys.exit(1)
    run_zap(sys.argv[1], sys.argv[2])
