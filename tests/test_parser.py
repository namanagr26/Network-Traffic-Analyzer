"""Checks that capture.parse_packet understands the main packet types (no root needed).
Run:  python tests/test_parser.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP

import capture

LOCAL = {"192.168.1.10", "127.0.0.1"}


def check(name, row, proto, direction, flags=None):
    assert row is not None, name + ": parsed to None"
    assert row[3] == proto, "%s: protocol %s != %s" % (name, row[3], proto)
    assert row[9] == direction, "%s: direction %s != %s" % (name, row[9], direction)
    if flags is not None:
        assert row[8] == flags, "%s: flags %r != %r" % (name, row[8], flags)
    print("PASS", name, row)


syn = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=40000, dport=443, flags="S")
check("TCP SYN out", capture.parse_packet(syn, LOCAL), "TCP", "outgoing", "S")

synack = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=443, dport=40000, flags="SA")
check("TCP SYN-ACK in", capture.parse_packet(synack, LOCAL), "TCP", "incoming", "SA")

dns = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
check("DNS query", capture.parse_packet(dns, LOCAL), "DNS", "outgoing")

icmp = Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP()
check("ICMP ping", capture.parse_packet(icmp, LOCAL), "ICMP", "outgoing")

arp = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.10")
check("ARP", capture.parse_packet(arp, LOCAL), "ARP", "incoming")

lo = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=50000, dport=22, flags="S")
check("Loopback SYN", capture.parse_packet(lo, LOCAL), "TCP", "local", "S")

assert capture.parse_packet(Ether(), LOCAL) is None
print("\nAll parser tests passed.")
