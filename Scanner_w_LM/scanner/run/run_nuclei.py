import sys
import subprocess
from pathlib import Path

def run_nuclei(target: str, output: str):
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["nuclei", "-u", target, "-jsonl", "-o", output], check=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: run_nuclei.py <target_url> <output_file>")
        sys.exit(1)
    run_nuclei(sys.argv[1], sys.argv[2])
