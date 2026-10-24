#!/usr/bin/env bash
# Generates test traffic ONLY against your own machine (127.0.0.1) so you can
# trigger the detector. Never point these tools at anyone else's network.
#
# 1) Start capture in another terminal:  bash run_capture.sh
# 2) Let it run ~40 seconds with normal use so a "normal" level exists.
# 3) Run:  bash test_traffic.sh normal | spike | scan | ssh | all
cd "$(dirname "$0")"

normal() {
  echo "[*] Normal traffic..."
  ping -c 5 8.8.8.8 || true
  nslookup example.com || true
  curl -s -o /dev/null https://example.com || true
}

spike() {
  echo "[*] Traffic spike (ping flood on loopback)..."
  sudo ping -f -c 5000 127.0.0.1 > /dev/null
}

scan() {
  echo "[*] Port-scan-like behaviour (nmap on YOUR OWN loopback)..."
  sudo nmap -sS -p 1-200 127.0.0.1 > /dev/null
}

ssh_attempts() {
  echo "[*] Repeated connection attempts to port 22 (loopback)..."
  for i in $(seq 1 40); do
    (echo > /dev/tcp/127.0.0.1/22) 2>/dev/null || true
    sleep 0.2
  done
}

case "$1" in
  normal) normal ;;
  spike)  spike ;;
  scan)   scan ;;
  ssh)    ssh_attempts ;;
  all)    normal; spike; scan; ssh_attempts ;;
  *) echo "usage: bash test_traffic.sh normal|spike|scan|ssh|all" ;;
esac
echo "[*] Done. Now run:  ./venv/bin/python detector.py"
