#!/usr/bin/python

try:
    from scapy.all import *
except ImportError: # Old Scapy version?
    from scapy import *
import sys
import getopt

dst=None
dport = 53
qname = "www.slashdot.org"
max_fuzzy = 20

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

if dst == "127.0.0.1" or dst == "::1": # TODO: not sufficient because there are also global addresses that are on the machine
    old_setting=conf.L3socket
    conf.L3socket=L3RawSocket # http://wiki.spiritofhack.net/index.php/Scapy-erreurs#Je_ne_peux_pas_pinguer_127.0.0.1._Scapy_ne_marche_pas_avec_127.0.0.1_ni_localhost
    # Test it (Scapy bug #193 http://trac.secdev.org/scapy/ticket/193)
    try:
        sr1(p, timeout=0.01)
    except NameError:
        print >>sys.stderr, "Warning, setting the local link as raw failed (Scapy bug #193)"
        conf.L3socket=old_setting
    
p = IP(dst=dst)/UDP(sport=RandShort(),dport=dport)/DNS(rd=1,qd=DNSQR(qname=qname))

# Send a normal packet. We wait for an answer.
sr1(p)

# For wrong packets, we do not wait for an answer.

# Send a packet with a wrong qdcount
p.qdcount = 0
sr1(p, timeout=0.1)

p.qdcount = 2
sr1(p, timeout=0.1)

# Modify the length field of a label
s = str(p)
s2 = s[:44] + '\x030' + s[45:]
p2 = IP(s2)
p2[UDP].sport=RandShort()
del p2[UDP].chksum
sr1(p2, timeout=0.5, retry=-2)

# Truncates the packet
s2 = s[:-4]
p2 = IP(s2)
p2[UDP].sport=RandShort()
del p2[IP].len
del p2[IP].chksum
del p2[UDP].len 
del p2[UDP].chksum
sr1(p2, timeout=0.5, retry=-2)

# Fuzzy testing
f = IP(dst=dst)/UDP(sport=RandShort(),dport=dport)/fuzz(DNS(rd=1,qd=DNSQR(qname=qname)))
for i in range(0,max_fuzzy):
    sr1(f, timeout=0.1)

