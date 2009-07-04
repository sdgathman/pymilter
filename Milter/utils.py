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

ip4re = re.compile(r'^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$')

# from spf.py
def addr2bin(str):
  """Convert a string IPv4 address into an unsigned integer."""
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
	  u.append(unicode(s,enc))
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
  except email.Errors.HeaderParseError: pass
  return val
