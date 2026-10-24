#!/usr/bin/env bash
# Loads synthetic sample traffic and opens the dashboard (no root needed).
cd "$(dirname "$0")"
./venv/bin/python demo_data.py
echo "Opening dashboard at http://localhost:8501  (Ctrl+C to stop)"
./venv/bin/streamlit run dashboard.py
