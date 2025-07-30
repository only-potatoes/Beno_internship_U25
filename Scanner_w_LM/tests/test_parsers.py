# tests/test_parsers.py

from scanner.parse_nuclei import load_nuclei_results
from scanner.parse_nikto import load_nikto_results
from scanner.parse_zap import load_zap_results

def test_parsers():
    print("Nuclei:", len(load_nuclei_results("out/nuclei.json")), "findings")
    print("Nikto:", len(load_nikto_results("out/nikto.json")), "findings")
    print("ZAP:", len(load_zap_results("out/zap.json")), "findings")

if __name__ == "__main__":
    test_parsers()
