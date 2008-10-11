#!/usr/bin/python2.4

# Convert banned ip list to zonefile data suitable for use as a 
# DNS blacklist with BIND.  This is a way to share your banned ips
# with friends.

import socket
import sys
from glob import glob

banned_ips = [socket.inet_aton(ip) for fn in sys.argv[1:] for ip in open(fn)]
banned_ips.sort()
for ip in banned_ips:
  a = socket.inet_ntoa(ip).split('.')
  a.reverse()
  print "%s\tIN A 127.0.0.2"%('.'.join(a))
