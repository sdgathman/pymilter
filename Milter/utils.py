## @package Milter.utils
# Miscellaneous functions.
#

import re
import struct
import socket
import email.errors
from email.header import decode_header
import email.base64mime
import email.utils
from fnmatch import fnmatchcase
from binascii import a2b_base64

dnsre = re.compile(r'^[a-z][-a-z\d.]+$', re.IGNORECASE)
PAT_IP4 = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)
ip4re = re.compile(PAT_IP4+'$')
ip6re = re.compile(                 '(?:%(hex4)s:){6}%(ls32)s$'
                   '|::(?:%(hex4)s:){5}%(ls32)s$'
                  '|(?:%(hex4)s)?::(?:%(hex4)s:){4}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,1}%(hex4)s)?::(?:%(hex4)s:){3}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,2}%(hex4)s)?::(?:%(hex4)s:){2}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,3}%(hex4)s)?::%(hex4)s:%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,4}%(hex4)s)?::%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,5}%(hex4)s)?::%(hex4)s$'
    '|(?:(?:%(hex4)s:){0,6}%(hex4)s)?::$'
  % {
    'ls32': r'(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|%s)'%PAT_IP4,
    'hex4': r'[0-9a-f]{1,4}'
    }, re.IGNORECASE)

# from spf.py
def addr2bin(s):
  """Convert a string IPv4 address into an unsigned integer."""
  if s.find(':') >= 0:
    try:
      return bin2long6(inet_pton(s))
    except:
      raise socket.error("Invalid IP6 address: "+s)
  try:
    return struct.unpack("!L", socket.inet_aton(s))[0]
  except socket.error:
    raise socket.error("Invalid IP4 address: "+s)

def bin2long6(s):
    """Convert binary IP6 address into an unsigned Python long integer."""
    h, l = struct.unpack("!QQ", s)
    return h << 64 | l

if hasattr(socket,'has_ipv6') and socket.has_ipv6:
    def inet_ntop(s):
        return socket.inet_ntop(socket.AF_INET6,s)
    def inet_pton(s):
        return socket.inet_pton(socket.AF_INET6,s.strip())
else:
    from pyip6 import inet_ntop, inet_pton

MASK = 0xFFFFFFFF
MASK6 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

def cidr(i,n,mask=MASK):
  return ~(mask >> n) & mask & i

def iniplist(ipaddr,iplist):
  """Return whether ip is in cidr list
  >>> iniplist('66.179.26.146',['127.0.0.1','66.179.26.128/26'])
  True
  >>> iniplist('127.0.0.1',['127.0.0.1','66.179.26.128/26'])
  True
  >>> iniplist('192.168.0.45',['192.168.0.*'])
  True
  >>> iniplist('4.2.2.2',['b.resolvers.Level3.net'])
  True
  >>> iniplist('2606:2800:220:1::',['example.com/40'])
  True
  >>> iniplist('4.2.2.2',['nothing.example.com'])
  False
  >>> iniplist('2001:610:779:0:223:6cff:fe9a:9cf3',['127.0.0.1','172.20.1.0/24','2001:610:779::/48'])
  True
  >>> iniplist('2G01:610:779:0:223:6cff:fe9a:9cf3',['127.0.0.1','172.20.1.0/24','2001:610:779::/48'])
  Traceback (most recent call last):
    ...
  ValueError: Invalid ip syntax:2G01:610:779:0:223:6cff:fe9a:9cf3
  """
  if ip4re.match(ipaddr):
    fam = socket.AF_INET
    ipnum = addr2bin(ipaddr)
  elif ip6re.match(ipaddr):
    fam = socket.AF_INET6
    ipnum = bin2long6(inet_pton(ipaddr))
  else:
    raise ValueError('Invalid ip syntax:'+ipaddr)
  for pat in iplist:
    p = pat.split('/',1)
    if ip4re.match(p[0]):
      if len(p) > 1:
        n = int(p[1])
      else:
        n = 32
      if cidr(addr2bin(p[0]),n) == cidr(ipnum,n):
        return True
    elif ip6re.match(p[0]):
      if len(p) > 1:
        n = int(p[1])
      else:
        n = 128
      if cidr(bin2long6(inet_pton(p[0])),n,MASK6) == cidr(ipnum,n,MASK6):
        return True
    elif dnsre.match(p[0]):
      try:
        sfx = '/'.join(['']+p[1:])
        addrlist = [r[4][0]+sfx for r in socket.getaddrinfo(p[0],25,fam)]
        if iniplist(ipaddr,addrlist):
          return True
      except socket.gaierror: pass
    elif fnmatchcase(ipaddr,pat):
      return True
  return False

## Split email into Fullname and address.
# This replaces <code>email.utils.parseaddr</code> but fixes
# some <a href="http://bugs.python.org/issue1025395">tricky test cases</a>.
# Additional tricky cases are still broken.  Patches welcome.
#
def parseaddr(t):
  """Split email into Fullname and address.

  >>> parseaddr('user@example.com')
  ('', 'user@example.com')
  >>> parseaddr('"Full Name" <foo@example.com>')
  ('Full Name', 'foo@example.com')
  >>> parseaddr('spam@spammer.com <foo@example.com>')
  ('spam@spammer.com', 'foo@example.com')
  >>> parseaddr('God@heaven <@hop1.org,@hop2.net:jeff@spec.org>')
  ('God@heaven', 'jeff@spec.org')
  >>> parseaddr('Real Name ((comment)) <addr...@example.com>')
  ('Real Name (comment)', 'addr...@example.com')
  """
  #return email.utils.parseaddr(t)
  res = email.utils.parseaddr(t)
  # dirty fix for some broken cases
  if not res[0]:
    pos = t.find('<')
    if pos > 0 and t[-1] == '>':
      addrspec = t[pos+1:-1]
      pos1 = addrspec.rfind(':')
      if pos1 > 0:
        addrspec = addrspec[pos1+1:]
      return email.utils.parseaddr('"%s" <%s>' % (t[:pos].strip(),addrspec))
  if not res[1]:
    pos = t.find('<')
    if pos > 0 and t[-1] == '>':
      addrspec = t[pos+1:-1]
      pos1 = addrspec.rfind(':')
      if pos1 > 0:
        addrspec = addrspec[pos1+1:]
      return email.utils.parseaddr('%s<%s>' % (t[:pos].strip(),addrspec))
  return res

## Fix email.base64mime.decode to add any missing padding
def decode(s, convert_eols=None):
  if not s: return s
  while len(s) % 4: s += '='	# add missing padding
  dec = a2b_base64(s)
  if convert_eols:
      return dec.replace(CRLF, convert_eols)
  return dec
    
email.base64mime.decode = decode

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
  >>> parse_addr('@mx.example.com:user@example.com')
  ['user', 'example.com']
  >>> parse_addr('@user@example.com')
  ['@user', 'example.com']
  """
  if t.startswith('<') and t.endswith('>'): t = t[1:-1]
  if t.startswith('"'):
    if t.endswith('"'): return [t[1:-1]]
    pos = t.find('"@')
    if pos > 0: return [t[1:pos],t[pos+2:]]
  if t.startswith('@'):
    try: t = t.split(':',1)[1]
    except IndexError: pass
  return t.rsplit('@',1)

## Decode headers gratuitously encoded to hide the content.
# Spammers often encode headers to obscure the content from
# spam filters.  This function decodes gratuitously encoded
# headers.
# @param val    the raw header value
# @return the decoded value or the original raw value

def parse_header(val):
  """Decode headers gratuitously encoded to hide the content.
  """
  try:
    h = decode_header(val)
    if not len(h) or (not h[0][1] and len(h) == 1): return val
    u = []
    for s,enc in h:
      if enc:
        try:
          u.append(s.decode(enc,'replace'))
        except LookupError:
          u.append(s.decode())
      else:
        u.append(s.decode())
    u = u''.join(u)
    for enc in ('us-ascii','iso-8859-1','utf-8'):
      try:
        return u.encode(enc)
      except UnicodeError: continue
  except UnicodeDecodeError: pass
  except LookupError: pass
  except ValueError: pass
  except email.errors.HeaderParseError: pass
  return val
