#!/usr/bin/env bash
# One-time setup for Kali Linux. Run:  bash setup.sh
set -e
cd "$(dirname "$0")"

echo "[1/3] Installing system packages (needs sudo)..."
sudo apt update
sudo apt install -y python3-venv python3-pip git tcpdump libpcap-dev nmap

echo "[2/3] Creating virtual environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "[3/3] Checking the install..."
./venv/bin/python tests/test_parser.py
./venv/bin/python db.py

echo
echo "Setup complete. Next:  bash run_demo.sh   (sample data + dashboard)"
