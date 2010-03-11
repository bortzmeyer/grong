#!/usr/bin/python

from scapy.all import *
import sys
import getopt

dst=None
dport = 53
qname = "www.slashdot.org"

def usage(msg=None):
    print >>sys.stderr, "Usage: %s -s server-to-query [-p port-to-use] [-q query]" % sys.argv[0]
    if msg is not None:
        print >>sys.stderr, msg

try:
    optlist, args = getopt.getopt (sys.argv[1:], "s:p:q:h",
                               ["server=", "port=", "query", "help"])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        elif option == "--server" or option == "-s":
            dst = value
        elif option == "--query" or option == "-q":
            qname = value
        elif option == "--port" or option == "-p":
            dport = int(value)
        else:
            # Should never occur, it is trapped by getopt
            print >>sys.stderr, "Unknown option %s" % option
            usage()
            sys.exit(1)
except getopt.error, reason:
    usage(reason)
    sys.exit(1)
if len(args) != 0:
    usage()
    sys.exit(1)
if dst is None:
    usage()
    sys.exit(1)
    
p = IP(dst=dst)/UDP(sport=RandShort(),dport=dport)/DNS(rd=1,qd=DNSQR(qname=qname))

# Send a normal packet
sr1(p)

# Send a packet with a wrong qdcount
p.qdcount = 0
sr1(p)

p.qdcount = 2
sr1(p)

# Modify the length field of a label
s = str(p)
s2 = s[:44] + '\x030' + s[45:]
p2 = IP(s2)
p2[UDP].sport=RandShort()
del p2[UDP].chksum
sr1(p2, timeout=1.5, retry=-2)

# Truncates the packet
s2 = s[:-4]
p2 = IP(s2)
p2[UDP].sport=RandShort()
del p2[IP].len
del p2[IP].chksum
del p2[UDP].len 
del p2[UDP].chksum
sr1(p2, timeout=1.5, retry=-2)
