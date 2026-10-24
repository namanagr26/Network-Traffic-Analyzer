"""
demo_data.py - fills the database with SYNTHETIC traffic (no sniffing, no root needed).

Use it to build/test the dashboard and reports quickly, or to take screenshots.
For your real demo, also capture real traffic with capture.py.

    python demo_data.py            # wipe DB, create 30 minutes of fake traffic + attacks, run detector
    python demo_data.py --minutes 60
"""
import argparse
import random
import time

import config
import db
import detector

VM = "192.168.1.10"
LAN_HOSTS = ["192.168.1.1", "192.168.1.20", "192.168.1.50"]
SERVERS = ["142.250.77.14", "151.101.1.69", "104.18.32.7", "13.107.42.14",
           "172.217.160.78", "34.117.65.55", "8.8.8.8", "1.1.1.1"]


def _row(ts, src, dst, proto, sport, dport, size, flags, direction, service=""):
    return (ts, src, dst, proto, service, sport, dport, size, flags, direction)


def normal_second(t, rng, rate):
    rows = []
    for _ in range(max(1, int(rng.gauss(rate, rate * 0.3)))):
        ts = t + rng.random()
        server = rng.choice(SERVERS)
        r = rng.random()
        eph = rng.randint(32768, 60999)
        if r < 0.50:       # HTTPS
            if rng.random() < 0.5:
                rows.append(_row(ts, VM, server, "TCP", eph, 443, rng.randint(60, 600),
                                 rng.choice(["A", "PA"]), "outgoing", "HTTPS"))
            else:
                rows.append(_row(ts, server, VM, "TCP", 443, eph, rng.randint(200, 1500),
                                 rng.choice(["A", "PA"]), "incoming", "HTTPS"))
        elif r < 0.62:     # DNS
            rows.append(_row(ts, VM, "8.8.8.8", "DNS", eph, 53, rng.randint(70, 110), "", "outgoing", "DNS"))
            rows.append(_row(ts + 0.02, "8.8.8.8", VM, "DNS", 53, eph, rng.randint(90, 250), "", "incoming", "DNS"))
        elif r < 0.70:     # HTTP
            rows.append(_row(ts, server, VM, "TCP", 80, eph, rng.randint(300, 1500), "PA", "incoming", "HTTP"))
        elif r < 0.80:     # QUIC / other UDP
            rows.append(_row(ts, VM, server, "UDP", eph, 443, rng.randint(100, 1200), "", "outgoing", "HTTPS"))
        elif r < 0.85:     # ICMP
            rows.append(_row(ts, VM, server, "ICMP", None, None, 98, "", "outgoing"))
        elif r < 0.90:     # ARP
            rows.append(_row(ts, rng.choice(LAN_HOSTS), VM, "ARP", None, None, 42, "", "incoming"))
        elif r < 0.95:     # new outgoing connection
            rows.append(_row(ts, VM, server, "TCP", eph, 443, 74, "S", "outgoing", "HTTPS"))
        else:              # LAN chatter
            h = rng.choice(LAN_HOSTS)
            rows.append(_row(ts, h, VM, "UDP", 5353, 5353, rng.randint(80, 300), "", "incoming", "mDNS"))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--no-detect", action="store_true")
    ap.add_argument("--keep", action="store_true", help="do not wipe existing data")
    args = ap.parse_args()

    rng = random.Random(42)
    conn = db.get_conn()
    if not args.keep:
        db.reset(conn)

    end = time.time() - 5
    start = end - args.minutes * 60
    rows = []

    # --- normal background traffic, rate drifts between ~5 and ~14 packets/s
    t = start
    while t < end:
        rate = 9 + 5 * ((int(t) // 90) % 3 - 1) * 0.7
        rows += normal_second(t, rng, max(rate, 3))
        t += 1

    # --- baseline: every IP above is "normal"
    normal_ips = set(LAN_HOSTS + SERVERS + [VM])
    db.add_known_ips(conn, normal_ips, source="demo-baseline")

    # --- ATTACK 1: traffic spike (UDP flood from a LAN host) ~ 12 minutes ago
    t0 = end - 12 * 60
    for s in range(40):
        for _ in range(rng.randint(500, 700)):
            rows.append(_row(t0 + s + rng.random(), "192.168.1.50", VM, "UDP",
                             rng.randint(1024, 65000), 9999, rng.randint(200, 1400), "", "incoming"))

    # --- ATTACK 2: port scan from an unknown LAN IP ~ 8 minutes ago
    t0 = end - 8 * 60
    for i, port in enumerate(range(1, 201)):
        rows.append(_row(t0 + i * 0.03, "192.168.1.77", VM, "TCP", 44444, port, 60, "S",
                         "incoming", ""))

    # --- ATTACK 3: SSH brute-force-like attempts from an unknown external IP ~ 5 minutes ago
    t0 = end - 5 * 60
    for i in range(70):
        rows.append(_row(t0 + i * 0.6, "203.0.113.45", VM, "TCP", rng.randint(40000, 60000), 22, 60, "S",
                         "incoming", "SSH"))

    rows.sort(key=lambda r: r[0])
    db.insert_packets(conn, rows)
    print("[*] Inserted %d synthetic packets covering %d minutes." % (len(rows), args.minutes))

    if not args.no_detect:
        detector.run_detection(conn, lookback=0)


if __name__ == "__main__":
    main()
