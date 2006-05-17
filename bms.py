#!/usr/bin/env python
# A simple milter that has grown quite a bit.
# $Log$
# Revision 1.60  2006/05/12 16:14:48  customdesigned
# Don't require SPF pass for white/black listing mail from trusted relay.
# Support localpart wildcard for white and black lists.
#
# Revision 1.59  2006/04/06 18:14:17  customdesigned
# Check whitelist/blacklist even when not checking SPF (e.g. trusted relay).
#
# Revision 1.58  2006/03/10 20:52:49  customdesigned
# Use re to recognize failure DSNs.
#
# Revision 1.57  2006/03/07 20:50:54  customdesigned
# Use signed Message-ID in delayed reject to blacklist senders
#
# Revision 1.56  2006/02/24 02:12:54  customdesigned
# Properly report hard PermError (lax mode fails also) by always setting
# perm_error attribute with PermError exception.  Improve reporting of
# invalid domain PermError.
#
# Revision 1.55  2006/02/17 05:04:29  customdesigned
# Use SRS sign domain list.
# Accept but do not use for training whitelisted senders without SPF pass.
# Immediate rejection of unsigned bounces.
#
# Revision 1.54  2006/02/16 02:16:36  customdesigned
# User specific SPF receiver policy.
#
# Revision 1.53  2006/02/12 04:15:01  customdesigned
# Remove spf dependency for iniplist
#
# Revision 1.52  2006/02/12 02:12:08  customdesigned
# Use CIDR notation for internal connect list.
#
# Revision 1.51  2006/02/12 01:13:58  customdesigned
# Don't check rcpt user list when signed MFROM.
#
# Revision 1.50  2006/02/09 20:39:43  customdesigned
# Use CIDR notation for trusted_relay iplist
#
# Revision 1.49  2006/01/30 23:14:48  customdesigned
# put back eom condition
#
# Revision 1.48  2006/01/12 20:31:24  customdesigned
# Accelerate training via whitelist and blacklist.
#
# Revision 1.47  2005/12/29 04:49:10  customdesigned
# Do not auto-whitelist autoreplys
#
# Revision 1.46  2005/12/28 20:17:29  customdesigned
# Expire and renew AddrCache entries
#
# Revision 1.45  2005/12/23 22:34:46  customdesigned
# Put guessed result in separate header.
#
# Revision 1.44  2005/12/23 21:47:07  customdesigned
# Move Received-SPF header to top.
#
# Revision 1.43  2005/12/09 16:54:01  customdesigned
# Select neutral DSN template for best_guess
#
# Revision 1.42  2005/12/01 22:42:32  customdesigned
# improve gossip support.
# Initialize srs_domain from srs.srs config property.  Should probably
# always block unsigned DSN when signing all.
#
# Revision 1.41  2005/12/01 18:59:25  customdesigned
# Fix neutral policy.  pobox.com -> openspf.org
#
# Revision 1.40  2005/11/07 21:22:35  customdesigned
# GOSSiP support, local database only.
#
# Revision 1.39  2005/10/31 00:04:58  customdesigned
# Simple implementation of trusted_forwarder list.  Inefficient for
# more than 1 or 2 entries.
#
# Revision 1.38  2005/10/28 19:36:54  customdesigned
# Don't check internal_domains for trusted_relay.
#
# Revision 1.37  2005/10/28 09:30:49  customdesigned
# Do not send quarantine DSN when sender is DSN.
#
# Revision 1.36  2005/10/23 16:01:29  customdesigned
# Consider MAIL FROM a match for supply_sender when a subdomain of From or Sender
#
# Revision 1.35  2005/10/20 18:47:27  customdesigned
# Configure auto_whitelist senders.
#
# Revision 1.34  2005/10/19 21:07:49  customdesigned
# access.db stores keys in lower case
#
# Revision 1.33  2005/10/19 19:37:50  customdesigned
# Train screener on whitelisted messages.
#
# Revision 1.32  2005/10/14 16:17:31  customdesigned
# Auto whitelist refinements.
#
# Revision 1.31  2005/10/14 01:14:08  customdesigned
# Auto whitelist feature.
#
# Revision 1.30  2005/10/12 16:36:30  customdesigned
# Release 0.8.3
#
# Revision 1.29  2005/10/11 22:50:07  customdesigned
# Always check HELO except for SPF pass, temperror.
#
# Revision 1.28  2005/10/10 23:50:20  customdesigned
# Use logging module to make logging threadsafe (avoid splitting log lines)
#
# Revision 1.27  2005/10/10 20:15:33  customdesigned
# Configure SPF policy via sendmail access file.
#
# Revision 1.26  2005/10/07 03:23:40  customdesigned
# Banned users option.  Experimental feature to supply Sender when
# missing and MFROM domain doesn't match From.  Log cipher bits for
# SMTP AUTH.  Sketch access file feature.
#
# Revision 1.25  2005/09/08 03:55:08  customdesigned
# Handle perverse MFROM quoting.
#
# Revision 1.24  2005/08/18 03:36:54  customdesigned
# Don't innoculate with SCREENED mail.
#
# Revision 1.23  2005/08/17 19:35:27  customdesigned
# Send DSN before adding message to quarantine.
#
# Revision 1.22  2005/08/11 22:17:58  customdesigned
# Consider SMTP AUTH connections internal.
#
# Revision 1.21  2005/08/04 21:21:31  customdesigned
# Treat fail like softfail for selected (braindead) domains.
# Treat mail according to extended processing results, but
# report any PermError that would officially result via DSN.
#
# Revision 1.20  2005/08/02 18:04:35  customdesigned
# Keep screened honeypot mail, but optionally discard honeypot only mail.
#
# Revision 1.19  2005/07/20 03:30:04  customdesigned
# Check pydspam version for honeypot, include latest pyspf changes.
#
# Revision 1.18  2005/07/17 01:25:44  customdesigned
# Log as well as use extended result for best guess.
#
# Revision 1.17  2005/07/15 20:25:36  customdesigned
# Use extended results processing for best_guess.
#
# Revision 1.16  2005/07/14 03:23:33  customdesigned
# Make SES package optional.  Initial honeypot support.
#
# Revision 1.15  2005/07/06 04:05:40  customdesigned
# Initial SES integration.
#
# Revision 1.14  2005/07/02 23:27:31  customdesigned
# Don't match hostnames for internal connects.
#
# Revision 1.13  2005/07/01 16:30:24  customdesigned
# Always log trusted Received and Received-SPF headers.
#
# Revision 1.12  2005/06/20 22:35:35  customdesigned
# Setreply for rejectvirus.
#
# Revision 1.11  2005/06/17 02:07:20  customdesigned
# Release 0.8.1
#
# Revision 1.10  2005/06/16 18:35:51  customdesigned
# Ignore HeaderParseError decoding header
#
# Revision 1.9  2005/06/14 21:55:29  customdesigned
# Check internal_domains for outgoing mail.
#
# Revision 1.8  2005/06/06 18:24:59  customdesigned
# Properly log exceptions from pydspam
#
# Revision 1.7  2005/06/04 19:41:16  customdesigned
# Fix bugs from testing RPM
#
# Revision 1.6  2005/06/03 04:57:05  customdesigned
# Organize config reader by section.  Create defang section.
#
# Revision 1.5  2005/06/02 15:00:17  customdesigned
# Configure banned extensions.  Scan zipfile option with test case.
#
# Revision 1.4  2005/06/02 04:18:55  customdesigned
# Update copyright notices after reading article on /.
#
# Revision 1.3  2005/06/02 02:09:00  customdesigned
# Record timestamp in send_dsn.log
#
# Revision 1.2  2005/06/02 01:00:36  customdesigned
# Support configurable templates for DSNs.
#
# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2002,2003,2004,2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

import sys
import os
import StringIO
import rfc822
import mime
import email.Errors
import Milter
import tempfile
import ConfigParser
import time
import socket
import struct
import re
import gc
import anydbm
import Milter.dsn as dsn
from Milter.dynip import is_dynip as dynip

from fnmatch import fnmatchcase
from email.Header import decode_header

# Import gossip if available
try:
  import gossip
  from gossip.server import Gossip
except: gossip = None

# Import pysrs if available
try:
  import SRS
  srsre = re.compile(r'^SRS[01][+-=]',re.IGNORECASE)
except: SRS = None
try:
  import SES
except: SES = None

# Import spf if available
try: import spf
except: spf = None

ip4re = re.compile(r'^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$')

# Sometimes, MTAs reply to our DSN.  We recognize this type of reply/DSN
# and check for the original recipient SRS encoded in Message-ID.
# If found, we blacklist that recipient.
subjpats = (
 r'^failure notice',
 r'^returned mail',
 r'^undeliver',
 r'^delivery\b.*\bfailure',
 r'^delivery problem',
 r'\buser unknown\b',
 r'^failed',
 r'^echec de distribution',
 r'^fallo en la entrega'
)
refaildsn = re.compile('|'.join(subjpats),re.IGNORECASE)
import logging

# Thanks to Chris Liechti for config parsing suggestions

# Global configuration defaults suitable for test framework.
socketname = "/tmp/pythonsock"
reject_virus_from = ()
wiretap_users = {}
discard_users = {}
wiretap_dest = None
blind_wiretap = True
check_user = {}
block_forward = {}
hide_path = ()
log_headers = False
block_chinese = False
spam_words = ()
porn_words = ()
banned_exts = mime.extlist.split(',')
scan_zip = False
scan_html = True
scan_rfc822 = True
internal_connect = ()
trusted_relay = ()
trusted_forwarder = ()
internal_domains = ()
banned_users = ()
hello_blacklist = ()
smart_alias = {}
dspam_dict = None
dspam_users = {}
dspam_userdir = None
dspam_exempt = {}
dspam_whitelist = {}
whitelist_senders = {}
dspam_screener = ()
dspam_internal = True	# True if internal mail should be dspammed
dspam_reject = ()
dspam_sizelimit = 180000
srs = None
ses = None
srs_reject_spoofed = False
srs_domain = None
spf_reject_neutral = ()
spf_accept_softfail = ()
spf_accept_fail = ()
spf_best_guess = False
spf_reject_noptr = False
supply_sender = False
access_file = None
timeout = 600

logging.basicConfig(
	stream=sys.stdout,
	level=logging.INFO,
	format='%(asctime)s %(message)s',
	datefmt='%Y%b%d %H:%M:%S'
)
milter_log = logging.getLogger('milter')

if gossip:
  gossip_node = Gossip('gossip4.db',120)

class MilterConfigParser(ConfigParser.ConfigParser):

  def getlist(self,sect,opt):
    if self.has_option(sect,opt):
      return [q.strip() for q in self.get(sect,opt).split(',')]
    return []

  def getaddrset(self,sect,opt):
    if not self.has_option(sect,opt):
      return {}
    s = self.get(sect,opt)
    d = {}
    for q in s.split(','):
      q = q.strip()
      if q.startswith('file:'):
        domain = q[5:]
	d[domain] = d.setdefault(domain,[]) + open(domain,'r').read().split()
      else:
	user,domain = q.split('@')
	d.setdefault(domain,[]).append(user)
    return d
  
  def getaddrdict(self,sect,opt):
    if not self.has_option(sect,opt):
      return {}
    d = {}
    for q in self.get(sect,opt).split(','):
      q = q.strip()
      if self.has_option(sect,q):
        l = self.get(sect,q)
	for addr in l.split(','):
	  addr = addr.strip()
	  if addr.startswith('file:'):
	    fname = addr[5:]
	    for a in open(fname,'r').read().split():
	      d[a] = q
	  else:
	    d[addr] = q
    return d

  def getdefault(self,sect,opt,default=None):
    if self.has_option(sect,opt):
      return self.get(sect,opt)
    return default

def read_config(list):
  cp = MilterConfigParser({
    'tempdir': "/var/log/milter/save",
    'socket': "/var/run/milter/pythonsock",
    'timeout': '600',
    'scan_html': 'no',
    'scan_rfc822': 'yes',
    'scan_zip': 'no',
    'block_chinese': 'no',
    'log_headers': 'no',
    'blind_wiretap': 'yes',
    'maxage': '8',
    'hashlength': '8',
    'reject_spoofed': 'no',
    'reject_noptr': 'no',
    'supply_sender': 'no',
    'best_guess': 'no',
    'dspam_internal': 'yes'
  })
  cp.read(list)

  # milter section
  tempfile.tempdir = cp.get('milter','tempdir')
  global socketname, timeout, check_user, log_headers
  global internal_connect, internal_domains, trusted_relay, hello_blacklist
  socketname = cp.get('milter','socket')
  timeout = cp.getint('milter','timeout')
  check_user = cp.getaddrset('milter','check_user')
  log_headers = cp.getboolean('milter','log_headers')
  internal_connect = cp.getlist('milter','internal_connect')
  internal_domains = cp.getlist('milter','internal_domains')
  trusted_relay = cp.getlist('milter','trusted_relay')
  hello_blacklist = cp.getlist('milter','hello_blacklist')

  # defang section
  global scan_rfc822, scan_html, block_chinese, scan_zip, block_forward
  global banned_exts, porn_words, spam_words
  if cp.has_section('defang'):
    section = 'defang'
    # for backward compatibility,
    # banned extensions defaults to empty only when defang section exists
    banned_exts = cp.getlist(section,'banned_exts')
  else:	# use milter section if no defang section for compatibility
    section = 'milter'
  scan_rfc822 = cp.getboolean(section,'scan_rfc822')
  scan_zip = cp.getboolean(section,'scan_zip')
  scan_html = cp.getboolean(section,'scan_html')
  block_chinese = cp.getboolean(section,'block_chinese')
  block_forward = cp.getaddrset(section,'block_forward')
  porn_words = cp.getlist(section,'porn_words')
  spam_words = cp.getlist(section,'spam_words')

  # scrub section
  global hide_path, reject_virus_from
  hide_path = cp.getlist('scrub','hide_path')
  reject_virus_from = cp.getlist('scrub','reject_virus_from')

  # wiretap section
  global blind_wiretap, wiretap_users, wiretap_dest, discard_users
  blind_wiretap = cp.getboolean('wiretap','blind')
  wiretap_users = cp.getaddrset('wiretap','users')
  discard_users = cp.getaddrset('wiretap','discard')
  wiretap_dest = cp.getdefault('wiretap','dest')
  if wiretap_dest: wiretap_dest = '<%s>' % wiretap_dest

  global smart_alias
  for sa in cp.getlist('wiretap','smart_alias'):
    sm = cp.getlist('wiretap',sa)
    if len(sm) < 2:
      milter_log.warning('malformed smart alias: %s',sa)
      continue
    if len(sm) == 2: sm.append(sa)
    key = (sm[0],sm[1])
    smart_alias[key] = sm[2:]

  # dspam section
  global dspam_dict, dspam_users, dspam_userdir, dspam_exempt, dspam_internal
  global dspam_screener,dspam_whitelist,dspam_reject,dspam_sizelimit
  global whitelist_senders
  whitelist_senders = cp.getaddrset('dspam','whitelist_senders')
  dspam_dict = cp.getdefault('dspam','dspam_dict')
  dspam_exempt = cp.getaddrset('dspam','dspam_exempt')
  dspam_whitelist = cp.getaddrset('dspam','dspam_whitelist')
  dspam_users = cp.getaddrdict('dspam','dspam_users')
  dspam_userdir = cp.getdefault('dspam','dspam_userdir')
  dspam_screener = cp.getlist('dspam','dspam_screener')
  dspam_reject = cp.getlist('dspam','dspam_reject')
  dspam_internal = cp.getboolean('dspam','dspam_internal')
  if cp.has_option('dspam','dspam_sizelimit'):
    dspam_sizelimit = cp.getint('dspam','dspam_sizelimit')

  # spf section
  global spf_reject_neutral,spf_best_guess,SRS,spf_reject_noptr
  global spf_accept_softfail,spf_accept_fail,supply_sender,access_file
  global trusted_forwarder
  if spf:
    spf.DELEGATE = cp.getdefault('spf','delegate')
    spf_reject_neutral = cp.getlist('spf','reject_neutral')
    spf_accept_softfail = cp.getlist('spf','accept_softfail')
    spf_accept_fail = cp.getlist('spf','accept_fail')
    spf_best_guess = cp.getboolean('spf','best_guess')
    spf_reject_noptr = cp.getboolean('spf','reject_noptr')
    supply_sender = cp.getboolean('spf','supply_sender')
    access_file = cp.getdefault('spf','access_file')
    trusted_forwarder = cp.getlist('spf','trusted_forwarder')
  srs_config = cp.getdefault('srs','config')
  if srs_config: cp.read([srs_config])
  srs_secret = cp.getdefault('srs','secret')
  if SRS and srs_secret:
    global ses,srs,srs_reject_spoofed,srs_domain,banned_users
    database = cp.getdefault('srs','database')
    srs_reject_spoofed = cp.getboolean('srs','reject_spoofed')
    maxage = cp.getint('srs','maxage')
    hashlength = cp.getint('srs','hashlength')
    separator = cp.getdefault('srs','separator','=')
    if database:
      import SRS.DB
      srs = SRS.DB.DB(database=database,secret=srs_secret,
        maxage=maxage,hashlength=hashlength,separator=separator)
    else:
      srs = SRS.Guarded.Guarded(secret=srs_secret,
        maxage=maxage,hashlength=hashlength,separator=separator)
    if SES:
      ses = SES.new(secret=srs_secret,expiration=maxage)
      srs_domain = set(cp.getlist('srs','ses'))
    else:
      srs_domain = set(cp.getlist('srs','srs'))
    srs_domain.update(cp.getlist('srs','sign'))
    srs_domain.add(cp.getdefault('srs','fwdomain'))
    banned_users = cp.getlist('srs','banned_users')

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

class SPFPolicy(object):
  "Get SPF policy by result, defaulting to classic policy from pymilter.cfg"
  def __init__(self,sender):
    self.sender = sender
    self.domain = sender.split('@')[-1].lower()
    if access_file:
      try: acf = anydbm.open(access_file,'r')
      except: acf = None
    else: acf = None
    self.acf = acf

  def getPolicy(self,pfx):
    acf = self.acf
    if not acf: return None
    try:
      return acf[pfx + self.sender]
    except KeyError:
      try:
	return acf[pfx + self.domain]
      except KeyError:
	try:
	  return acf[pfx]
	except KeyError:
	  return None

  def getFailPolicy(self):
    policy = self.getPolicy('spf-fail:')
    if not policy:
      if self.domain in spf_accept_fail:
        policy = 'CBV'
      else:
	policy = 'REJECT'
    return policy

  def getNonePolicy(self):
    policy = self.getPolicy('spf-none:')
    if not policy:
      if spf_reject_noptr:
	policy = 'REJECT'
      else:
        policy = 'CBV'
    return policy

  def getSoftfailPolicy(self):
    policy = self.getPolicy('spf-softfail:')
    if not policy:
      if self.domain in spf_accept_softfail:
        policy = 'OK'
      elif self.domain in spf_reject_neutral:
        policy = 'REJECT'
      else:
        policy = 'CBV'
    return policy

  def getNeutralPolicy(self):
    policy = self.getPolicy('spf-neutral:')
    if not policy:
      if self.domain in spf_reject_neutral:
        policy = 'REJECT'
      policy = 'OK'
    return policy

  def getPermErrorPolicy(self):
    policy = self.getPolicy('spf-permerror:')
    if not policy:
      policy = 'REJECT'
    return policy

  def getPassPolicy(self):
    policy = self.getPolicy('spf-pass:')
    if not policy:
      policy = 'OK'
    return policy

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

class AddrCache(object):
  time_format = '%Y%b%d %H:%M:%S %Z'

  def __init__(self,renew=7):
    self.age = renew

  def load(self,fname,age=0):
    if not age:
      age = self.age
    self.fname = fname
    cache = {}
    self.cache = cache
    now = time.time()
    try:
      too_old = now - age*24*60*60	# max age in days
      for ln in open(self.fname):
	try:
	  rcpt,ts = ln.strip().split(None,1)
	  l = time.strptime(ts,AddrCache.time_format)
	  t = time.mktime(l)
	  if t > too_old:
	    cache[rcpt.lower()] = (t,None)
	except:
	  cache[ln.strip().lower()] = (now,None)
    except IOError: pass

  def has_key(self,sender):
    try:
      ts,res = self.cache[sender.lower()]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if ts > too_old:
        return True
      del self.cache[sender.lower()]
      try:
	user,host = sender.split('@',1)
	return self.has_key(host)
      except ValueError:
        pass
    except KeyError:
      try:
	user,host = sender.split('@',1)
	return self.has_key(host)
      except ValueError:
        pass
    return False

  def __getitem__(self,sender):
    try:
      ts,res = self.cache[sender.lower()]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if ts > too_old:
	return res
      del self.cache[sender.lower()]
      raise KeyError, sender
    except KeyError,x:
      try:
	user,host = sender.split('@',1)
	return self.__getitem__(host)
      except ValueError:
        raise x

  def __setitem__(self,sender,res):
    lsender = sender.lower()
    now = time.time()
    cached = self.has_key(sender)
    if not cached:
      self.cache[lsender] = (now,res)
      if not res:
	s = time.strftime(AddrCache.time_format,time.localtime(now))
	print >>open(self.fname,'a'),sender,s # log refreshed senders

  def __len__(self):
    return len(self.cache)

cbv_cache = AddrCache(renew=7)
cbv_cache.load('send_dsn.log',age=7)
auto_whitelist = AddrCache(renew=30)
auto_whitelist.load('auto_whitelist.log',age=120)
try:
  blacklist = set(open('blacklist.log').read().split())
except:
  blacklist = {}

class bmsMilter(Milter.Milter):
  """Milter to replace attachments poisonous to Windows with a WARNING message,
     check SPF, and other anti-forgery features, and implement wiretapping
     and smart alias redirection."""

  def log(self,*msg):
    milter_log.info('[%d] %s',self.id,' '.join([str(m) for m in msg]))

  def __init__(self):
    self.tempname = None
    self.mailfrom = None	# sender in SMTP form
    self.canon_from = None	# sender in end user form
    self.fp = None
    self.bodysize = 0
    self.id = Milter.uniqueID()

  # delrcpt can only be called from eom().  This accumulates recipient
  # changes which can then be applied by alter_recipients()
  def del_recipient(self,rcpt):
    rcpt = rcpt.lower()
    if not rcpt in self.discard_list:
      self.discard_list.append(rcpt)

  # addrcpt can only be called from eom().  This accumulates recipient
  # changes which can then be applied by alter_recipients()
  def add_recipient(self,rcpt):
    rcpt = rcpt.lower()
    if not rcpt in self.redirect_list:
      self.redirect_list.append(rcpt)

  # addheader can only be called from eom().  This accumulates added headers
  # which can then be applied by alter_headers()
  def add_header(self,name,val,idx=-1):
    self.new_headers.append((name,val,idx))
    self.log('%s: %s' % (name,val))

  def connect(self,hostname,unused,hostaddr):
    self.internal_connection = False
    self.trusted_relay = False
    # sometimes people put extra space in sendmail config, so we strip
    self.receiver = self.getsymval('j').strip()
    if hostaddr and len(hostaddr) > 0:
      ipaddr = hostaddr[0]
      if iniplist(ipaddr,internal_connect):
	self.internal_connection = True
      if iniplist(ipaddr,trusted_relay):
        self.trusted_relay = True
    else: ipaddr = ''
    self.connectip = ipaddr
    self.missing_ptr = dynip(hostname,self.connectip)
    if self.internal_connection:
      connecttype = 'INTERNAL'
    else:
      connecttype = 'EXTERNAL'
    if self.trusted_relay:
      connecttype += ' TRUSTED'
    if self.missing_ptr:
      connecttype += ' DYN'
    self.log("connect from %s at %s %s" % (hostname,hostaddr,connecttype))
    self.hello_name = None
    self.connecthost = hostname
    if hostname == 'localhost' and not ipaddr.startswith('127.') \
    or hostname == '.':
      self.log("REJECT: PTR is",hostname)
      self.setreply('550','5.7.1', '"%s" is not a reasonable PTR name'%hostname)
      return Milter.REJECT
    return Milter.CONTINUE

  def hello(self,hostname):
    self.hello_name = hostname
    self.log("hello from %s" % hostname)
    if ip4re.match(hostname):
      self.log("REJECT: numeric hello name:",hostname)
      self.setreply('550','5.7.1','hello name cannot be numeric ip')
      return Milter.REJECT
    if not self.internal_connection and hostname in hello_blacklist:
      self.log("REJECT: spam from self:",hostname)
      self.setreply('550','5.7.1',
	'Your mail server lies.  Its name is *not* %s.' % hostname)
      return Milter.REJECT
    if hostname == 'GC':
      n = gc.collect()
      self.log("gc:",n,' unreachable objects')
      self.log("auto-whitelist:",len(auto_whitelist),' entries')
      self.log("cbv_cache:",len(cbv_cache),' entries')
      self.setreply('550','5.7.1','%d unreachable objects'%n)
      return Milter.REJECT
    return Milter.CONTINUE

  def smart_alias(self,to):
    if smart_alias:
      t = parse_addr(to.lower())
      if len(t) == 2:
	ct = '@'.join(t)
      else:
	ct = t[0]
      cf = self.canon_from
      cf0 = cf.split('@',1)
      if len(cf0) == 2:
	cf0 = '@' + cf0[1]
      else:
	cf0 = cf
      for key in ((cf,ct),(cf0,ct)):
	if smart_alias.has_key(key):
	  self.del_recipient(to)
	  for t in smart_alias[key]:
	    self.add_recipient('<%s>'%t)

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  def envfrom(self,f,*str):
    self.log("mail from",f,str)
    self.fp = StringIO.StringIO()
    self.tempname = None
    self.mailfrom = f
    self.forward = True
    self.bodysize = 0
    self.hidepath = False
    self.discard = False
    self.dspam = True
    self.whitelist = False
    self.blacklist = False
    self.reject_spam = True
    self.data_allowed = True
    self.delayed_failure = None
    self.trust_received = self.trusted_relay
    self.trust_spf = self.trusted_relay
    self.redirect_list = []
    self.discard_list = []
    self.new_headers = []
    self.recipients = []
    self.cbv_needed = None
    self.whitelist_sender = False
    t = parse_addr(f)
    if len(t) == 2: t[1] = t[1].lower()
    self.canon_from = '@'.join(t)
    # Some braindead MTAs can't be relied upon to properly flag DSNs.
    # This heuristic tries to recognize such.
    self.is_bounce = (f == '<>' or t[0].lower() in banned_users
        #and t[1] == self.hello_name
    )

    # Check SMTP AUTH, also available:
    #   auth_authen  authenticated user
    #   auth_author  (ESMTP AUTH= param)
    #   auth_ssf     (connection security, 0 = unencrypted)
    #   auth_type    (authentication method, CRAM-MD5, DIGEST-MD5, PLAIN, etc)
    # cipher_bits  SSL encryption strength
    # cert_subject SSL cert subject
    # verify       SSL cert verified

    self.user = self.getsymval('{auth_authen}')
    if self.user:
      # Very simple SMTP AUTH policy by defaul:
      #   any successful authentication is considered INTERNAL
      # FIXME: configure allowed MAIL FROM by user
      self.internal_connection = True
      self.log(
        "SMTP AUTH:",self.user, self.getsymval('{auth_type}'),
        "sslbits =",self.getsymval('{cipher_bits}'),
        "ssf =",self.getsymval('{auth_ssf}'), "INTERNAL"
      )
      if self.getsymval('{verify}'):
	self.log("SSL AUTH:",
	  self.getsymval('{cert_subject}'),
	  "verify =",self.getsymval('{verify}')
	)

    self.fp.write('From %s %s\n' % (self.canon_from,time.ctime()))
    if len(t) == 2:
      user,domain = t
      if not self.internal_connection:
        if not self.trusted_relay:
	  for pat in internal_domains:
	    if fnmatchcase(domain,pat):
	      self.log("REJECT: spam from self",pat)
	      self.setreply('550','5.7.1','I hate talking to myself.')
	      return Milter.REJECT
      else:
        if internal_domains:
	  for pat in internal_domains:
	    if fnmatchcase(domain,pat): break
	  else:
	    self.log("REJECT: zombie PC at ",self.connectip,
	    	" sending MAIL FROM ",self.canon_from)
	    self.setreply('550','5.7.1',
	    'Your PC is using an unauthorized MAIL FROM.',
	    'It is either badly misconfigured or controlled by organized crime.'
	    )
	    return Milter.REJECT
	wl_users = whitelist_senders.get(domain,())
	if user in wl_users or '' in wl_users:
	  self.whitelist_sender = True
	  
      self.rejectvirus = domain in reject_virus_from
      if user in wiretap_users.get(domain,()):
        self.add_recipient(wiretap_dest)
	self.smart_alias(wiretap_dest)
      if user in discard_users.get(domain,()):
	self.discard = True
      exempt_users = dspam_whitelist.get(domain,())
      if user in exempt_users or '' in exempt_users:
	self.dspam = False
    else:
      self.rejectvirus = False
      domain = None
    if not self.hello_name:
      self.log("REJECT: missing HELO")
      self.setreply('550','5.7.1',"It's polite to say HELO first.")
      return Milter.REJECT
    self.umis = None
    self.spf = None
    if not (self.internal_connection or self.trusted_relay)	\
    	and self.connectip and spf:
      rc = self.check_spf()
    else:
      rc = Milter.CONTINUE
    # FIXME: parse Received-SPF from trusted_relay for SPF result
    res = self.spf and self.spf.guess
    # Check whitelist and blacklist
    if auto_whitelist.has_key(self.canon_from):
      if res == 'pass' or self.trusted_relay:
	self.whitelist = True
	self.log("WHITELIST",self.canon_from)
      else:
        self.dspam = False
	self.log("PROBATION",self.canon_from)
    elif cbv_cache.has_key(self.canon_from) and cbv_cache[self.canon_from] \
    	or domain in blacklist:
      self.blacklist = True
      self.log("BLACKLIST",self.canon_from)
    if gossip and domain and rc == Milter.CONTINUE:
      if self.spf and self.spf.result == 'pass':
        qual = 'SPF'
      else:
        qual = self.connectip
      self.umis = gossip.umis(domain+qual,self.id+time.time())
      res,hdr,val = gossip_node.query(self.umis,domain,qual,1)
      self.add_header(hdr,val)
    return rc

  def check_spf(self):
    receiver = self.receiver
    for tf in trusted_forwarder:
      q = spf.query(self.connectip,'',tf,receiver=receiver,strict=False)
      res,code,txt = q.check()
      if res == 'pass':
        self.log("TRUSTED_FORWARDER:",tf)
        break
    else:
      q = spf.query(self.connectip,self.canon_from,self.hello_name,
	  receiver=receiver,strict=False)
      q.set_default_explanation(
	'SPF fail: see http://openspf.org/why.html?sender=%s&ip=%s' % (q.s,q.i))
      res,code,txt = q.check()
    q.result = res
    if res in ('unknown','permerror') and q.perm_error and q.perm_error.ext:
      self.cbv_needed = (q,res)	# report SPF syntax error to sender
      res,code,txt = q.perm_error.ext	# extended (lax processing) result
      txt = 'EXT: ' + txt
    p = SPFPolicy(q.s)
    if res not in ('pass','error','temperror'):
      if self.mailfrom != '<>':
	# check hello name via spf unless spf pass
	h = spf.query(self.connectip,'',self.hello_name,receiver=receiver)
	hres,hcode,htxt = h.check()
	if hres in ('deny','fail','neutral','softfail'):
	  self.log('REJECT: hello SPF: %s 550 %s' % (hres,htxt))
	  self.setreply('550','5.7.1',htxt,
	    "The hostname given in your MTA's HELO response is not listed",
	    "as a legitimate MTA in the SPF records for your domain.  If you",
	    "get this bounce, the message was not in fact a forgery, and you",
	    "should IMMEDIATELY notify your email administrator of the problem."
	  )
	  return Milter.REJECT
	if hres == 'none' and spf_best_guess \
	  and not dynip(self.hello_name,self.connectip):
	  hres,hcode,htxt = h.best_guess()
      else: hres = res
      ores = res
      if spf_best_guess and res == 'none':
	#self.log('SPF: no record published, guessing')
	q.set_default_explanation(
		'SPF guess: see http://openspf.org/why.html')
	# best_guess should not result in fail
	if self.missing_ptr:
	  # ignore dynamic PTR for best guess
	  res,code,txt = q.best_guess('v=spf1 a/24 mx/24')
	else:
	  res,code,txt = q.best_guess()
      if self.missing_ptr and ores == 'none' and res != 'pass' \
      		and hres != 'pass':
	policy = p.getNonePolicy()
	if policy == 'CBV':
	  if self.mailfrom != '<>':
	    self.cbv_needed = (q,ores)	# accept, but inform sender via DSN
	elif policy != 'OK':
	  self.log('REJECT: no PTR, HELO or SPF')
	  self.setreply('550','5.7.1',
    "You must have a valid HELO or publish SPF: http://www.openspf.org ",
    "Contact your mail administrator IMMEDIATELY!  Your mail server is ",
    "severely misconfigured.  It has no PTR record (dynamic PTR records ",
    "that contain your IP don't count), an invalid or dynamic HELO, ",
    "and no SPF record."
	  )
	  return Milter.REJECT
    if res in ('deny', 'fail'):
      policy = p.getFailPolicy()
      if hres == 'pass' and policy == 'CBV':
	if self.mailfrom != '<>':
	  self.cbv_needed = (q,res)
      elif policy != 'OK':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	self.setreply(str(code),'5.7.1',txt)
	# A proper SPF fail error message would read:
	# forger.biz [1.2.3.4] is not allowed to send mail with the domain
	# "forged.org" in the sender address.  Contact <postmaster@forged.org>.
	return Milter.REJECT
    if res == 'softfail':
      policy = p.getSoftfailPolicy()
      if policy == 'CBV' and hres == 'pass':
	if self.mailfrom != '<>':
	  self.cbv_needed = (q,res)
      elif policy != 'OK':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	self.setreply('550','5.7.1',
	  'SPF softfail: If you get this Delivery Status Notice, your email',
	  'was probably legitimate.  Your administrator has published SPF',
	  'records in a testing mode.  The SPF record reported your email as',
	  'a forgery, which is a mistake if you are reading this.  Please',
	  'notify your administrator of the problem immediately.'
	)
	return Milter.REJECT
    if res == 'neutral':
      policy = p.getNeutralPolicy()
      if policy == 'CBV' and hres == 'pass':
	if self.mailfrom != '<>':
	  self.cbv_needed = (q,res)
	  # FIXME: this makes Received-SPF show wrong result
      elif policy != 'OK':
	self.log('REJECT: SPF neutral for',q.s)
	self.setreply('550','5.7.1',
	  'mail from %s must pass SPF: http://openspf.org/why.html' % q.o,
	  'The %s domain is one that spammers love to forge.  Due to' % q.o,
	  'the volume of forged mail, we can only accept mail that',
	  'the SPF record for %s explicitly designates as legitimate.' % q.o,
	  'Sending your email through the recommended outgoing SMTP',
	  'servers for %s should accomplish this.' % q.o
	)
	return Milter.REJECT
    if res in ('unknown','permerror'):
      policy = p.getPermErrorPolicy()
      if policy == 'CBV' and hres == 'pass':
	if self.mailfrom != '<>':
	  self.cbv_needed = (q,res)
      elif policy != 'OK':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	# latest SPF draft recommends 5.5.2 instead of 5.7.1
	self.setreply(str(code),'5.5.2',txt,
	  'There is a fatal syntax error in the SPF record for %s' % q.o,
	  'We cannot accept mail from %s until this is corrected.' % q.o
	)
	return Milter.REJECT
    if res in ('error','temperror'):
      self.log('TEMPFAIL: SPF %s %i %s' % (res,code,txt))
      self.setreply(str(code),'4.3.0',txt)
      return Milter.TEMPFAIL
    self.add_header('Received-SPF',q.get_header(q.result,receiver),0)
    q.guess = res
    if res != q.result:
      self.add_header('X-Guessed-SPF',res,0)
    self.spf = q
    return Milter.CONTINUE

  # hide_path causes a copy of the message to be saved - until we
  # track header mods separately from body mods - so use only
  # in emergencies.
  def envrcpt(self,to,*str):
    # mail to MAILER-DAEMON is generally spam that bounced
    if to.startswith('<MAILER-DAEMON@'):
      self.log('DISCARD: RCPT TO:',to,str)
      return Milter.DISCARD
    self.log("rcpt to",to,str)
    t = parse_addr(to)
    newaddr = False
    if len(t) == 2:
      t[1] = t[1].lower()
      user,domain = t
      if self.is_bounce and srs and domain in srs_domain:
	oldaddr = '@'.join(parse_addr(to))
	try:
	  if ses:
	    newaddr = ses.verify(oldaddr)
	  else:
	    newaddr = oldaddr,
	  if len(newaddr) > 1:
            newaddr = newaddr[0]
	    self.log("ses rcpt:",newaddr)
	  else:
	    newaddr = srs.reverse(oldaddr)
	    # Currently, a sendmail map reverses SRS.  We just log it here.
	    self.log("srs rcpt:",newaddr)
	  self.dspam = False	# verified as reply to mail we sent
	except:
	  if not (self.internal_connection or self.trusted_relay):
	    if srsre.match(oldaddr):
	      self.log("REJECT: srs spoofed:",oldaddr)
	      self.setreply('550','5.7.1','Invalid SRS signature')
	      return Milter.REJECT
	    if oldaddr.startswith('SES='):
	      self.log("REJECT: ses spoofed:",oldaddr)
	      self.setreply('550','5.7.1','Invalid SES signature')
	      return Milter.REJECT
	    # reject for certain recipients are delayed until after DATA
	    if srs_reject_spoofed \
		and not user.lower() in ('postmaster','abuse'):
	      return self.forged_bounce()
	    self.data_allowed = not srs_reject_spoofed

      # non DSN mail to SRS address will bounce due to invalid local part
      canon_to = '@'.join(t)
      self.recipients.append(canon_to)
      # FIXME: use newaddr to check rcpt
      users = check_user.get(domain)
      if self.discard:
        self.del_recipient(to)
      # don't check userlist if signed MFROM for now
      if users and not newaddr and not user.lower() in users:
        self.log('REJECT: RCPT TO:',to)
	return Milter.REJECT
      if user in block_forward.get(domain,()):
        self.forward = False
      exempt_users = dspam_exempt.get(domain,())
      if user in exempt_users or '' in exempt_users:
	self.dspam = False
      if domain in hide_path:
        self.hidepath = True
      if not domain in dspam_reject:
        self.reject_spam = False
    self.smart_alias(to)
    # get recipient after virtusertable aliasing
    #rcpt = self.getsymval("{rcpt_addr}")
    #self.log("rcpt-addr",rcpt);
    return Milter.CONTINUE

  # Heuristic checks for spam headers
  def check_header(self,name,val):
    lname = name.lower()
    # val is decoded header value
    if lname == 'subject':
      
      # check for common spam keywords
      for wrd in spam_words:
        if val.find(wrd) >= 0:
	  self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1','That subject is not allowed')
	  return Milter.REJECT

      # even if we wanted the Taiwanese spam, we can't read Chinese
      if block_chinese:
	if val.startswith('=?big5') or val.startswith('=?ISO-2022-JP'):
	  self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1',"We don't understand chinese")
	  return Milter.REJECT

      # check for spam that claims to be legal
      lval = val.lower().strip()
      for adv in ("adv:","adv.","adv ","[adv]","(adv)","advt:","advert:"):
        if lval.startswith(adv):
	  self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1','Advertising not accepted here')
	  return Milter.REJECT
      for adv in ("adv","(adv)","[adv]"):
        if lval.endswith(adv):
	  self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1','Advertising not accepted here')
	  return Milter.REJECT

      # check for porn keywords
      for w in porn_words:
        if lval.find(w) >= 0:
          self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1','That subject is not allowed')
          return Milter.REJECT

      # check for annoying forwarders
      if not self.forward:
	if lval.startswith("fwd:") or lval.startswith("[fw"):
	  self.log('REJECT: %s: %s' % (name,val))
	  self.setreply('550','5.7.1','I find unedited forwards annoying')
	  return Milter.REJECT

      # check for delayed bounce of CBV
      if self.is_bounce and srs:
        if refaildsn.match(lval):
	  self.delayed_failure = val.strip()
	  # if confirmed by finding our signed Message-ID, 
	  # original sender (encoded in Message-ID) is blacklisted

    # check for invalid message id
    if lname == 'message-id' and len(val) < 4:
      self.log('REJECT: %s: %s' % (name,val))
      return Milter.REJECT

    # check for common bulk mailers
    if lname == 'x-mailer':
      mailer = val.lower()
      if mailer in ('direct email','calypso','mail bomber') \
	or mailer.find('optin') >= 0:
        self.log('REJECT: %s: %s' % (name,val))
        return Milter.REJECT
    return Milter.CONTINUE

  def forged_bounce(self):
    if self.mailfrom != '<>':
      self.log("REJECT: bogus DSN")
      self.setreply('550','5.7.1',
	"I do not accept normal mail from %s." % self.mailfrom.split('@')[0],
	"All such mail has turned out to be Delivery Status Notifications",
	"which failed to be marked as such.  Please send a real DSN if",
	"you need to.  Use another MAIL FROM if you need to send me mail."
      )
    else:
      self.log('REJECT: bounce with no SRS encoding')
      self.setreply('550','5.7.1',
	"I did not send you that message. Please consider implementing SPF",
	"(http://openspf.org) to avoid bouncing mail to spoofed senders.",
	"Thank you."
      )
    return Milter.REJECT
    
  def header(self,name,hval):
    if not self.data_allowed:
      return self.forged_bounce()
	  
    lname = name.lower()
    # decode near ascii text to unobfuscate
    val = parse_header(hval)
    if not self.internal_connection and not (self.blacklist or self.whitelist):
      rc = self.check_header(name,val)
      if rc != Milter.CONTINUE: return rc
    elif self.whitelist_sender and lname == 'subject':
	# check for AutoReplys
	vl = val.lower()
	if vl.startswith('read:')	\
	or vl.find('autoreply:') >= 0 or vl.startswith('return receipt'):
	  self.whitelist_sender = False
	  self.log('AUTOREPLY: not whitelisted')

    # log selected headers
    if log_headers or lname in ('subject','x-mailer'):
      self.log('%s: %s' % (name,val))
    elif self.trust_received and lname == 'received':
      self.trust_received = False
      self.log('%s: %s' % (name,val.splitlines()[0]))
    elif self.trust_spf and lname == 'received-spf':
      self.trust_spf = False
      self.log('%s: %s' % (name,val.splitlines()[0]))
    if self.fp:
      try:
        val = val.encode('us-ascii')
      except:
	val = hval
      self.fp.write("%s: %s\n" % (name,val))	# add header to buffer
    return Milter.CONTINUE

  def eoh(self):
    if not self.fp: return Milter.TEMPFAIL	# not seen by envfrom
    if not self.data_allowed:
      return self.forged_bounce()
    for name,val,idx in self.new_headers:
      self.fp.write("%s: %s\n" % (name,val))	# add new headers to buffer
    self.fp.write("\n")				# terminate headers
    # log when neither sender nor from domains matches mail from domain
    if supply_sender and self.mailfrom != '<>' and not self.internal_connection:
      mf_domain = self.canon_from.split('@')[-1]
      self.fp.seek(0)
      msg = rfc822.Message(self.fp)
      for rn,hf in msg.getaddrlist('from')+msg.getaddrlist('sender'):
	t = parse_addr(hf)
	if len(t) == 2:
	  hd = t[1].lower()
	  if hd == mf_domain or mf_domain.endswith('.'+hd): break
      else:
	for f in msg.getallmatchingheaders('from'):
	  self.log(f)
	sender = msg.getallmatchingheaders('sender')
	if sender:
	  for f in sender:
	    self.log(f)
	else:
	  self.log("NOTE: Supplying MFROM as Sender");
	  self.add_header('Sender',self.mailfrom)
      del msg
    # copy headers to a temp file for scanning the body
    self.fp.seek(0)
    headers = self.fp.getvalue()
    self.fp.close()
    fd,fname = tempfile.mkstemp(".defang")
    self.tempname = fname
    self.fp = os.fdopen(fd,"w+b")
    self.fp.write(headers)	# IOError (e.g. disk full) causes TEMPFAIL
    # check if headers are really spammy
    if dspam_dict and not self.internal_connection:
      ds = dspam.dspam(dspam_dict,dspam.DSM_PROCESS,
        dspam.DSF_CHAINED|dspam.DSF_CLASSIFY)
      try:
        ds.process(headers)
        if ds.probability > 0.93 and self.dspam and not self.whitelist:
          self.log('REJECT: X-DSpam-HeaderScore: %f' % ds.probability)
	  self.setreply('550','5.7.1','Your Message looks spammy')
	  return Milter.REJECT
	self.add_header('X-DSpam-HeaderScore','%f'%ds.probability)
      finally:
        ds.destroy()
    return Milter.CONTINUE

  def body(self,chunk):		# copy body to temp file
    if self.fp:
      self.fp.write(chunk)	# IOError causes TEMPFAIL in milter
      self.bodysize += len(chunk)
    return Milter.CONTINUE

  def _headerChange(self,msg,name,value):
    if value:	# add header
      self.addheader(name,value)
    else:	# delete all headers with name
      h = msg.getheaders(name)
      if h:
	for i in range(len(h),0,-1):
	  self.chgheader(name,i-1,'')

  def _chk_ext(self,name):
    "Check a name for dangerous Winblows extensions."
    if not name: return name
    lname = name.lower()
    for ext in self.bad_extensions:
      if lname.endswith(ext): return name
    return None

    
  def _chk_attach(self,msg):
    "Filter attachments by content."
    # check for bad extensions
    mime.check_name(msg,self.tempname,ckname=self._chk_ext,scan_zip=scan_zip)
    # remove scripts from HTML
    if scan_html:
      mime.check_html(msg,self.tempname)	
    # don't let a tricky virus slip one past us
    if scan_rfc822:
      msg = msg.get_submsg()
      if isinstance(msg,email.Message.Message):
	return mime.check_attachments(msg,self._chk_attach)
    return Milter.CONTINUE

  def alter_recipients(self,discard_list,redirect_list):
    for rcpt in discard_list:
      if rcpt in redirect_list: continue
      self.log("DISCARD RCPT: %s" % rcpt)	# log discarded rcpt
      self.delrcpt(rcpt)
    for rcpt in redirect_list:
      if rcpt in discard_list: continue
      self.log("APPEND RCPT: %s" % rcpt)	# log appended rcpt
      self.addrcpt(rcpt)
      if not blind_wiretap:
        self.addheader('Cc',rcpt)

  # check spaminess for recipients in dictionary groups
  # if there are multiple users getting dspammed, then
  # a signature tag for each is added to the message.

  # FIXME: quarantine messages rejected via fixed patterns above
  #	   this will give a fast start to stats

  def check_spam(self):
    "return True/False if self.fp, else return Milter.REJECT/TEMPFAIL/etc"
    if not dspam_userdir: return False
    ds = Dspam.DSpamDirectory(dspam_userdir)
    ds.log = self.log
    ds.headerchange = self._headerChange
    modified = False
    for rcpt in self.recipients:
      if dspam_users.has_key(rcpt.lower()):
        user = dspam_users.get(rcpt.lower())
	if user:
	  try:
	    self.fp.seek(0)
	    txt = self.fp.read()
	    if user == 'spam' and self.internal_connection:
	      sender = dspam_users.get(self.canon_from)
	      if sender:
	        self.log("SPAM: %s" % sender)	# log user for FP
		ds.add_spam(sender,txt)
		txt = None
		self.fp = None
		return Milter.DISCARD
	    elif user == 'falsepositive' and self.internal_connection:
	      sender = dspam_users.get(self.canon_from)
	      if sender:
	        self.log("FP: %s" % sender)	# log user for FP
	        txt = ds.false_positive(sender,txt)
		self.fp = StringIO.StringIO(txt)
		self.delrcpt('<%s>' % rcpt)
		self.recipients = None
		self.rejectvirus = False
		return True
	    elif not self.internal_connection or dspam_internal:
	      if len(txt) > dspam_sizelimit:
		self.log("Large message:",len(txt))
		return False
	      if user == 'honeypot' and Dspam.VERSION >= '1.1.9':
	        keep = False	# keep honeypot mail
		self.fp = None
	        if len(self.recipients) > 1:
		  self.log("HONEYPOT:",rcpt,'SCREENED')
		  if self.whitelist:
		    # don't train when recipients includes honeypot
		    return False
		  if self.spf and self.mailfrom != '<>':
		    # check that sender accepts quarantine DSN
		    msg = mime.message_from_file(StringIO.StringIO(txt))
		    rc = self.send_dsn(self.spf,msg,'quarantine.txt')
		    del msg
		    if rc != Milter.CONTINUE:
		      return rc	
		  ds.check_spam(user,txt,self.recipients,quarantine=True,
		  	force_result=dspam.DSR_ISSPAM)
		else:
		  ds.check_spam(user,txt,self.recipients,quarantine=keep,
		  	force_result=dspam.DSR_ISSPAM)
		  self.log("HONEYPOT:",rcpt)
		return Milter.DISCARD
	      if self.whitelist:
	        # Sender whitelisted: tag, but force as ham.  
		# User can change if actually spam.
	        txt = ds.check_spam(user,txt,self.recipients,
			force_result=dspam.DSR_ISINNOCENT)
	      elif self.blacklist:
	        txt = ds.check_spam(user,txt,self.recipients,
			force_result=dspam.DSR_ISSPAM)
	      else:
		txt = ds.check_spam(user,txt,self.recipients)
	      if not txt:
	        # DISCARD if quarrantined for any recipient.  It
		# will be resent to all recipients if they submit
		# as a false positive.
		self.log("DSPAM:",user,rcpt)
		self.fp = None
		return Milter.DISCARD
	      self.fp = StringIO.StringIO(txt)
	      modified = True
	  except Exception,x:
	    self.log("check_spam:",x)
	    milter_log.error("check_spam: %s",x,exc_info=True)
    # screen if no recipients are dspam_users
    if not modified and dspam_screener and not self.internal_connection \
    	and self.dspam:
      self.fp.seek(0)
      txt = self.fp.read()
      if len(txt) > dspam_sizelimit:
	self.log("Large message:",len(txt))
	return False
      screener = dspam_screener[self.id % len(dspam_screener)]
      if not ds.check_spam(screener,txt,self.recipients,
      	classify=True,quarantine=False):
	if self.whitelist:
	  # messages is whitelisted but looked like spam, Train on Error
	  self.log("TRAIN:",screener,'X-Dspam-Score: %f' % ds.probability)
	  # user can't correct anyway if really spam, so discard tag
	  ds.check_spam(screener,txt,self.recipients,
		  force_result=dspam.DSR_ISINNOCENT)
	  return False
	if self.reject_spam:
	  self.log("DSPAM:",screener,
	  	'REJECT: X-DSpam-Score: %f' % ds.probability)
	  self.setreply('550','5.7.1','Your Message looks spammy')
	  self.fp = None
	  return Milter.REJECT
	self.log("DSPAM:",screener,"SCREENED")
	if self.spf and self.mailfrom != '<>':
	  # check that sender accepts quarantine DSN
	  self.fp.seek(0)
	  msg = mime.message_from_file(self.fp)
	  rc = self.send_dsn(self.spf,msg,'quarantine.txt')
	  if rc != Milter.CONTINUE:
	    self.fp = None
	    return rc
	  del msg
	if not ds.check_spam(screener,txt,self.recipients,classify=True):
	  self.fp = None
	  return Milter.DISCARD
	# Message no longer looks spammy, deliver normally. We lied in the DSN.
      elif self.blacklist:
        # message is blacklisted but looked like ham, Train on Error
	self.log("TRAINSPAM:",screener,'X-Dspam-Score: %f' % ds.probability)
	ds.check_spam(screener,txt,self.recipients,quarantine=False,
		force_result=dspam.DSR_ISSPAM)
	self.fp = None
	return Milter.DISCARD
      elif self.whitelist and ds.totals[1] < 1000:
	self.log("TRAIN:",screener,'X-Dspam-Score: %f' % ds.probability)
	# user can't correct anyway if really spam, so discard tag
	ds.check_spam(screener,txt,self.recipients,
		force_result=dspam.DSR_ISINNOCENT)
	return False
    return modified

  # train late in eom(), after failed CBV
  # FIXME: need to undo if registered as ham with a dspam_user
  def train_spam(self):
    "Train screener with current message as spam"
    if not dspam_userdir: return
    if not dspam_screener: return
    ds = Dspam.DSpamDirectory(dspam_userdir)
    ds.log = self.log
    self.fp.seek(0)
    txt = self.fp.read()
    if len(txt) > dspam_sizelimit:
      self.log("Large message:",len(txt))
      return
    screener = dspam_screener[self.id % len(dspam_screener)]
    # since message will be rejected, we do not quarantine
    ds.check_spam(screener,txt,self.recipients,force_result=dspam.DSR_ISSPAM,
    	quarantine=False)
    self.log("TRAINSPAM:",screener,'X-Dspam-Score: %f' % ds.probability)

  def eom(self):
    if not self.fp:
      return Milter.ACCEPT	# no message collected - so no eom processing

    try:
      # check for delayed bounce
      if self.delayed_failure:
        self.fp.seek(0)
	for ln in self.fp:
	  if ln.lower().startswith('message-id:'):
	    name,val = ln.split(None,1)
	    pos = val.find('<SRS')
	    if pos >= 0:
	      try:
		sender = srs.reverse(val[pos+1:-1])
		cbv_cache[sender] = 500,self.delayed_failure,time.time()
		try:
		  # save message for debugging
		  fname = tempfile.mktemp(".dsn")
		  os.rename(self.tempname,fname)
		except:
		  fname = self.tempname
		self.tempname = None
		self.log('BLACKLIST:',sender,fname)
		return Milter.DISCARD
	      except: continue

      # analyze external mail for spam
      spam_checked = self.check_spam()	# tag or quarantine for spam
      if not self.fp:
        if gossip and self.umis:
	  gossip_node.feedback(self.umis,1)
        return spam_checked

      # analyze all mail for dangerous attachments and scripts
      self.fp.seek(0)
      msg = mime.message_from_file(self.fp)
      # pass header changes in top level message to sendmail
      msg.headerchange = self._headerChange

      # filter leaf attachments through _chk_attach
      assert not msg.ismodified()
      self.bad_extensions = ['.' + x for x in banned_exts]
      rc = mime.check_attachments(msg,self._chk_attach)
    except:	# milter crashed trying to analyze mail
      exc_type,exc_value = sys.exc_info()[0:2]
      if dspam_userdir and exc_type == dspam.error:
        if not exc_value.strerror:
	  exc_value.strerror = exc_value.args[0]
	if exc_value.strerror == 'Lock failed':
	  milter_log.warn("LOCK: BUSY")	# log filename
	  self.setreply('450','4.2.0',
		'Too busy discarding spam.  Please try again later.')
	  return Milter.TEMPFAIL
      fname = tempfile.mktemp(".fail")	# save message that caused crash
      os.rename(self.tempname,fname)
      self.tempname = None
      if exc_type == email.Errors.BoundaryError:
	milter_log.warn("MALFORMED: %s",fname)	# log filename
        if self.internal_connection:
	  # accept anyway for now
	  return Milter.ACCEPT
	self.setreply('554','5.7.7',
		'Boundary error in your message, are you a spammer?')
        return Milter.REJECT
      if exc_type == email.Errors.HeaderParseError:
	milter_log.warn("MALFORMED: %s",fname)	# log filename
	self.setreply('554','5.7.7',
		'Header parse error in your message, are you a spammer?')
        return Milter.REJECT
      milter_log.error("FAIL: %s",fname)	# log filename
      # let default exception handler print traceback and return 451 code
      raise
    if rc == Milter.REJECT: return rc;
    if rc == Milter.DISCARD: return rc;

    if rc == Milter.CONTINUE: rc = Milter.ACCEPT # for testbms.py compat

    defanged = msg.ismodified()

    if self.hidepath: del msg['Received']

    if self.recipients == None:
      # false positive being recirculated
      self.recipients = msg.get_all('x-dspam-recipients',[])
      if self.recipients:
	for rcptlist in self.recipients:
	  for rcpt in rcptlist.split(','):
	    self.addrcpt('<%s>' % rcpt.strip())
	del msg['x-dspam-recipients']
      else:
	self.addrcpt(self.mailfrom)
    else:
      self.alter_recipients(self.discard_list,self.redirect_list)
      # auto whitelist original recipients
      if not defanged and self.whitelist_sender:
	for canon_to in self.recipients:
	  user,domain = canon_to.split('@')
	  if internal_domains:
	    for pat in internal_domains:
	      if fnmatchcase(domain,pat): break
	    else:
	      auto_whitelist[canon_to] = None
	      self.log('Auto-Whitelist:',canon_to)
	  else:
	    auto_whitelist[canon_to] = None
	    self.log('Auto-Whitelist:',canon_to)

    for name,val,idx in self.new_headers:
      try:
	self.addheader(name,val,idx)
      except:
	self.addheader(name,val)	# older sendmail can't insheader

    if self.cbv_needed:
      q,res = self.cbv_needed
      if res in ('softfail','fail','deny'):
	template_name = 'softfail.txt'
      elif res in ('unknown','permerror'):
	template_name = 'permerror.txt'
      elif res == 'neutral':
        template_name = 'neutral.txt'
      else:
	template_name = 'strike3.txt'
      rc = self.send_dsn(q,msg,template_name)
      self.cbv_needed = None
      if rc == Milter.REJECT:
	self.train_spam()
	return Milter.DISCARD
      if rc != Milter.CONTINUE:
        return rc

    if not defanged and not spam_checked:
      os.remove(self.tempname)
      self.tempname = None	# prevent re-removal
      self.log("eom")
      return rc			# no modified attachments

    # Body modified, copy modified message to a temp file 
    if defanged:
      if self.rejectvirus and not self.hidepath:
	self.log("REJECT virus from",self.mailfrom)
	self.setreply('550','5.7.1','Attachment type not allowed.',
		'You attempted to send an attachment with a banned extension.')
	self.tempname = None
	return Milter.REJECT
      self.log("Temp file:",self.tempname)
      self.tempname = None	# prevent removal of original message copy
    out = tempfile.TemporaryFile()
    try:
      msg.dump(out)
      out.seek(0)
      msg = rfc822.Message(out)
      msg.rewindbody()
      while True:
	buf = out.read(8192)
	if len(buf) == 0: break
	self.replacebody(buf)	# feed modified message to sendmail
      if spam_checked: 
	if gossip and self.umis:
	  gossip_node.feedback(self.umis,0)
        self.log("dspam")
      return rc
    finally:
      out.close()
    return Milter.TEMPFAIL

  def send_dsn(self,q,msg,template_name):
    sender = q.s
    cached = cbv_cache.has_key(sender)
    if cached:
      self.log('CBV:',sender,'(cached)')
      res = cbv_cache[sender]
    else:
      self.log('CBV:',sender)
      try:
	template = file(template_name).read()
      except IOError: template = None
      m = dsn.create_msg(q,self.recipients,msg,template)
      if srs:
	msgid = srs.forward(sender,self.receiver)
	m.add_header('Message-Id','<%s>'%msgid)
	#m.add_header('Sender','"Python Milter" <%s>'%msgid)
      m = m.as_string()
      print >>open('last_dsn','w'),m
      res = dsn.send_dsn(sender,self.receiver,m)
    if res:
      desc = "CBV: %d %s" % res[:2]
      if 400 <= res[0] < 500:
	self.log('TEMPFAIL:',desc)
	self.setreply('450','4.2.0',*desc.splitlines())
	return Milter.TEMPFAIL
      if len(res) < 3: res += time.time(),
      cbv_cache[sender] = res
      self.log('REJECT:',desc)
      self.setreply('550','5.7.1',*desc.splitlines())
      return Milter.REJECT
    cbv_cache[sender] = res
    return Milter.CONTINUE

  def close(self):
    if self.tempname:
      os.remove(self.tempname)	# remove in case session aborted
    if self.fp:
      self.fp.close()
    
    return Milter.CONTINUE

  def abort(self):
    self.log("abort after %d body chars" % self.bodysize)
    return Milter.CONTINUE

def main():
  Milter.factory = bmsMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  if wiretap_dest or smart_alias or dspam_userdir:
    flags = flags + Milter.ADDRCPT
  if srs or len(discard_users) > 0 or smart_alias or dspam_userdir:
    flags = flags + Milter.DELRCPT
  Milter.set_flags(flags)
  milter_log.info("bms milter startup")
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,timeout)
  milter_log.info("bms milter shutdown")

if __name__ == "__main__":
  read_config(["/etc/mail/pymilter.cfg","milter.cfg"])
  if dspam_dict:
    import dspam	# low level spam check
  if dspam_userdir:
    import dspam
    import Dspam	# high level spam check
    try:
      dspam_version = Dspam.VERSION
    except:
      dspam_version = '1.1.4'
    assert dspam_version >= '1.1.5'
  main()
