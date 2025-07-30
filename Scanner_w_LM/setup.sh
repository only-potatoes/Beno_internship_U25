#!/bin/bash

echo "[*] Setting up environment..."

# --- 1. Python virtual environment
python3 -m venv venv
source venv/bin/activate

# --- 2. Upgrade pip
pip install --upgrade pip

# --- 3. Install Python dependencies
pip install openai python-dotenv requests aiohttp tqdm

# --- 4. Install Nikto (if not present)
if ! command -v nikto &> /dev/null; then
    echo "[*] Installing Nikto..."
    brew install nikto || sudo apt install nikto -y
fi

# --- 5. Install OWASP ZAP (GUI included)
if ! command -v zap.sh &> /dev/null; then
    echo "[*] Installing OWASP ZAP..."
    brew install --cask owasp-zap || echo "[!] Please install ZAP manually from https://www.zaproxy.org/download/"
fi

# --- 6. Install Go (if not installed) and Nuclei
if ! command -v go &> /dev/null; then
    echo "[*] Installing Go..."
    brew install go || sudo apt install golang-go -y
fi

echo "[*] Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin

# --- 7. Pull Nuclei templates
nuclei -update-templates

echo "[✓] Setup complete! Activate with: source venv/bin/activate"
