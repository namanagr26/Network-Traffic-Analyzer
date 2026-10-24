#!/usr/bin/env bash
# Starts REAL packet capture (needs root). Extra arguments are passed through:
#   bash run_capture.sh --iface eth0
cd "$(dirname "$0")"
sudo ./venv/bin/python capture.py "$@"
