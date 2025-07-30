#!/usr/bin/env python3

import sys
import subprocess
from pathlib import Path

def run_nikto(target: str, output: str):
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    cmd = ["/opt/homebrew/bin/nikto", "-h", target, "-Format", "csv", "-output", output]

    print(f"[+] Running Nikto on {target}...\n")
    result = subprocess.run(cmd, capture_output=True, text=True)

    print("[Nikto STDOUT]")
    print(result.stdout)
    print("\n[Nikto STDERR]")
    print(result.stderr)

    if result.returncode != 0:
        print(f"\n[!] Nikto exited with code {result.returncode} (non-fatal if findings were written).")
    else:
        print(f"\n[+] Nikto completed successfully.")

    if Path(output).exists():
        print(f"[+] Nikto results saved to: {output}")
    else:
        print(f"[!] Nikto output file not found: {output} — something went wrong.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: run_nikto.py <target_url> <output_file.csv>")
        sys.exit(1)

    run_nikto(sys.argv[1], sys.argv[2])
