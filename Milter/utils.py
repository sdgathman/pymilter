import re
import struct
import socket
from fnmatch import fnmatchcase

ip4re = re.compile(r'^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$')

# from spf.py
def addr2bin(str):
  "Convert a string IPv4 address into an unsigned integer."
  return struct.unpack("!L", socket.inet_aton(str))[0]

MASK = 0xFFFFFFFFL

def cidr(i,n):
  return ~(MASK >> n) & MASK & i

def iniplist(ipaddr,iplist):
  """Return whether ip is in cidr list
  >>> iniplist('66.179.26.146',['127.0.0.1','66.179.26.128/26'])
  True
  >>> iniplist('127.0.0.1',['127.0.0.1','66.179.26.128/26'])
  True
  >>> iniplist('192.168.0.45',['192.168.0.*'])
  True
  """
  ipnum = addr2bin(ipaddr)
  for pat in iplist:
    p = pat.split('/',1)
    if ip4re.match(p[0]):
      if len(p) > 1:
	n = int(p[1])
      else:
        n = 32
      if cidr(addr2bin(p[0]),n) == cidr(ipnum,n):
        return True
    elif fnmatchcase(ipaddr,pat):
      return True
  return False

def parse_addr(t):
  """Split email into user,domain.

  >>> parse_addr('user@example.com')
  ['user', 'example.com']
  >>> parse_addr('"user@example.com"')
  ['user@example.com']
  >>> parse_addr('"user@bar"@example.com')
  ['user@bar', 'example.com']
  >>> parse_addr('foo')
  ['foo']
  """
  if t.startswith('<') and t.endswith('>'): t = t[1:-1]
  if t.startswith('"'):
    if t.endswith('"'): return [t[1:-1]]
    pos = t.find('"@')
    if pos > 0: return [t[1:pos],t[pos+2:]]
  return t.split('@')
