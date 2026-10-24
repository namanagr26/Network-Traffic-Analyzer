"""
capture.py - MODULE 1: Network Packet Capture

Sniffs packets with Scapy, extracts the useful fields and stores them in SQLite.

Run (needs root, and must use the venv's python):
    sudo ./venv/bin/python capture.py                 # capture on all interfaces
    sudo ./venv/bin/python capture.py --iface eth0    # one interface
    sudo ./venv/bin/python capture.py --duration 60   # stop after 60 seconds
Stop with Ctrl+C.

Only captures traffic on YOUR OWN machine/network for learning purposes.
"""
import argparse
import collections
import os
import socket
import sys
import time

import psutil
from scapy.all import AsyncSniffer, ARP, DNS, ICMP, IP, IPv6, TCP, UDP

import config
import db

SERVICES = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 3306: "MySQL", 3389: "RDP",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def fix_perms():
    """Capture runs as root, so the database it creates would be read-only for the
    detector and dashboard (which run as your normal user). Open it up to everyone."""
    for suffix in ("", "-wal", "-shm"):
        p = config.DB_PATH + suffix
        try:
            if os.path.exists(p):
                os.chmod(p, 0o666)
        except OSError:
            pass


def get_local_ips():
    """All IP addresses that belong to this machine (used to decide direction)."""
    ips = {"127.0.0.1", "::1"}
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(a.address.split("%")[0])
    return ips


def get_direction(src, dst, local_ips):
    s, d = src in local_ips, dst in local_ips
    if s and d:
        return "local"
    if s:
        return "outgoing"
    if d:
        return "incoming"
    return "transit"


def parse_packet(pkt, local_ips):
    """Turn one Scapy packet into a tuple matching db.PACKET_COLUMNS.
    Returns None for packets we do not care about (e.g. non-IP, non-ARP)."""
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
        l3 = "IPv4"
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        l3 = "IPv6"
    elif pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
        l3 = "ARP"
    else:
        return None

    sport = dport = None
    flags = ""

    if l3 == "ARP":
        proto = "ARP"
    elif pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = "TCP"
        sport, dport = int(tcp.sport), int(tcp.dport)
        flags = str(tcp.flags)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto = "UDP"
        sport, dport = int(udp.sport), int(udp.dport)
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif l3 == "IPv6" and pkt[IPv6].nh == 58:
        proto = "ICMPv6"
    else:
        proto = "Other"

    if pkt.haslayer(DNS):
        proto = "DNS"

    service = SERVICES.get(dport) or SERVICES.get(sport) or ""
    direction = get_direction(src, dst, local_ips)
    return (float(pkt.time), src, dst, proto, service, sport, dport,
            len(pkt), flags, direction)


def main():
    ap = argparse.ArgumentParser(description="Network Traffic Analyzer - packet capture")
    ap.add_argument("--iface", default=config.INTERFACE,
                    help="interface name, or 'any' (default from config.py)")
    ap.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    ap.add_argument("--filter", default=None, help="optional BPF filter, e.g. 'tcp port 80'")
    args = ap.parse_args()

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Packet capture needs root. Run:\n    sudo ./venv/bin/python capture.py")
        sys.exit(1)

    conn = db.get_conn()
    fix_perms()
    local_ips = get_local_ips()
    buffer = collections.deque()
    print("[*] Database :", config.DB_PATH)
    print("[*] Interface:", args.iface)
    print("[*] Local IPs:", ", ".join(sorted(local_ips)))
    print("[*] Capturing... press Ctrl+C to stop.\n")

    def on_packet(pkt):
        try:
            row = parse_packet(pkt, local_ips)
        except Exception:      # a malformed packet must never kill the capture
            return
        if row:
            buffer.append(row)

    # Scapy does not understand the name "any", so expand it to every active interface.
    if args.iface == "any":
        iface = [n for n, st in psutil.net_if_stats().items() if st.isup]
        print("[*] Active interfaces:", ", ".join(iface))
    else:
        iface = args.iface

    sniffer = AsyncSniffer(iface=iface, prn=on_packet, store=False,
                           filter=args.filter)
    sniffer.start()
    time.sleep(1.0)
    err = getattr(sniffer, "exception", None)
    if err or not sniffer.running:
        print("[!] Sniffer failed to start: %s" % (err or "unknown error"))
        print("    Check the interface name with:  ip a")
        sys.exit(1)

    started = time.time()
    total = 0
    try:
        while True:
            time.sleep(config.FLUSH_INTERVAL)
            rows = []
            while buffer:
                rows.append(buffer.popleft())
            if rows:
                total += db.insert_packets(conn, rows)
                fix_perms()
            print("\r[*] packets saved: %-8d (last batch: %d)   " % (total, len(rows)),
                  end="", flush=True)
            if args.count and total >= args.count:
                break
            if args.duration and time.time() - started >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        rows = list(buffer)
        total += db.insert_packets(conn, rows)
        print("\n[*] Stopped. Total packets saved this session: %d" % total)


if __name__ == "__main__":
    main()
