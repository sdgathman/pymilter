## @package Milter.utils
# Miscellaneous functions.
#

import re
import struct
import socket
import email.Errors
from fnmatch import fnmatchcase
from email.Header import decode_header
#import email.Utils
import rfc822

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

MASK = 0xFFFFFFFFL
MASK6 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL

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
  >>> iniplist('2001:610:779:0:223:6cff:fe9a:9cf3',['127.0.0.1','172.20.1.0/24','2001:610:779::/48'])
  True
  >>> iniplist('2G01:610:779:0:223:6cff:fe9a:9cf3',['127.0.0.1','172.20.1.0/24','2001:610:779::/48'])
  Traceback (most recent call last):
    ...
  ValueError: Invalid ip syntax:2G01:610:779:0:223:6cff:fe9a:9cf3
  """
  if ip4re.match(ipaddr):
    ipnum = addr2bin(ipaddr)
  elif ip6re.match(ipaddr):
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
    elif fnmatchcase(ipaddr,pat):
      return True
  return False

## Split email into Fullname and address.
# This replaces <code>email.Utils.parseaddr</code> but fixes
# some <a href="http://bugs.python.org/issue1025395">tricky test cases</a>.
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
  ('Real Name', 'addr...@example.com')
  >>> parseaddr('a(WRONG)@b')
  ('WRONG', 'a@b')
  """
  #return email.Utils.parseaddr(t)
  res = rfc822.parseaddr(t)
  # dirty fix for some broken cases
  if not res[0]:
    pos = t.find('<')
    if pos > 0 and t[-1] == '>':
      addrspec = t[pos+1:-1]
      pos1 = addrspec.rfind(':')
      if pos1 > 0:
        addrspec = addrspec[pos1+1:]
      return rfc822.parseaddr('"%s" <%s>' % (t[:pos].strip(),addrspec))
  if not res[1]:
    pos = t.find('<')
    if pos > 0 and t[-1] == '>':
      addrspec = t[pos+1:-1]
      pos1 = addrspec.rfind(':')
      if pos1 > 0:
        addrspec = addrspec[pos1+1:]
      return rfc822.parseaddr('%s<%s>' % (t[:pos].strip(),addrspec))
  return res
    

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
          u.append(unicode(s,enc,'replace'))
        except LookupError:
          u.append(unicode(s))
      else:
        u.append(unicode(s))
    u = ''.join(u)
    for enc in ('us-ascii','iso-8859-1','utf8'):
      try:
        return u.encode(enc)
      except UnicodeError: continue
  except UnicodeDecodeError: pass
  except LookupError: pass
  except ValueError: pass
  except email.Errors.HeaderParseError: pass
  return val
