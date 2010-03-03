#!/usr/bin/scapy

src="127.0.0.1"
dst="127.0.0.1"
dport = 8053
qname = "www.slashdot.org"

if src == "127.0.0.1" or src == "::1":
    conf.L3socket = L3RawSocket
p = IP(src=src, dst=dst)/UDP(sport=RandShort(),dport=dport)/DNS(rd=1,qd=DNSQR(qname=qname))
