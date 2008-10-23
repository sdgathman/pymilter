#!/usr/bin/python2.4

import socket
import sys

banned_ips = set(socket.inet_aton(ip) 
    for fn in sys.argv[1:]
    for ip in open(fn))
banned_ips = list(banned_ips)
banned_ips.sort()
for ip in banned_ips:
  a = socket.inet_ntoa(ip).split('.')
  a.reverse()
  print "%s\tIN A 127.0.0.2"%('.'.join(a))
