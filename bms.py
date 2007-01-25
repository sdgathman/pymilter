#!/usr/bin/env python
# A simple milter that has grown quite a bit.
# $Log$
# Revision 1.90  2007/01/23 19:46:20  customdesigned
# Add private relay.
#
# Revision 1.89  2007/01/22 02:46:01  customdesigned
# Convert tabs to spaces.
#
# Revision 1.88  2007/01/19 23:31:38  customdesigned
# Move parse_header to Milter.utils.
# Test case for delayed DSN parsing.
# Fix plock when source missing or cannot set owner/group.
#
# Revision 1.87  2007/01/18 16:48:44  customdesigned
# Doc update.
# Parse From header for delayed failure detection.
# Don't check reputation of trusted host.
# Track IP reputation only when missing PTR.
#
# Revision 1.86  2007/01/16 05:17:29  customdesigned
# REJECT after data for blacklisted emails - so in case of mistakes, a
# legitimate sender will know what happened.
#
# Revision 1.85  2007/01/11 04:31:26  customdesigned
# Negative feedback for bad headers.  Purge cache logs on startup.
#
# Revision 1.84  2007/01/10 04:44:25  customdesigned
# Documentation updates.
#
# Revision 1.83  2007/01/08 23:20:54  customdesigned
# Get user feedback.
#
# Revision 1.82  2007/01/06 04:21:30  customdesigned
# Add config file to spfmilter
#
# Revision 1.81  2007/01/05 23:33:55  customdesigned
# Make blacklist an AddrCache
#
# Revision 1.80  2007/01/05 23:12:12  customdesigned
# Move parse_addr, iniplist, ip4re to Milter.utils
#
# Revision 1.79  2007/01/05 21:25:40  customdesigned
# Move AddrCache to Milter package.
#
# Revision 1.78  2007/01/04 18:01:10  customdesigned
# Do plain CBV when template missing.
#
# Revision 1.77  2006/12/31 03:07:20  customdesigned
# Use HELO identity if good when MAILFROM is bad.
#
# Revision 1.76  2006/12/30 18:58:53  customdesigned
# Skip reputation/whitelist/blacklist when rejecting on SPF.  Add X-Hello-SPF.
#
# Revision 1.75  2006/12/28 01:54:32  customdesigned
# Reject on bad_reputation or blacklist and nodspam.  Match valid helo like
# PTR for guessed SPF pass.
#
# Revision 1.74  2006/12/19 00:59:30  customdesigned
# Add archive option to wiretap.
#
# Revision 1.73  2006/12/04 18:47:03  customdesigned
# Reject multiple recipients to DSN.
# Auto-disable gossip on DB error.
#
# Revision 1.72  2006/11/22 16:31:22  customdesigned
# SRS domains were missing srs_reject check when SES was active.
#
# Revision 1.71  2006/11/22 01:03:28  customdesigned
# Replace last use of deprecated rfc822 module.
#
# Revision 1.70  2006/11/21 18:45:49  customdesigned
# Update a use of deprecated rfc822.  Recognize report-type=delivery-status
#
# See ChangeLog
#
# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2002,2003,2004,2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

import sys
import os
import StringIO
import mime
import email.Errors
import Milter
import tempfile
import time
import socket
import re
import shutil
import gc
import anydbm
import Milter.dsn as dsn
from Milter.dynip import is_dynip as dynip
from Milter.utils import iniplist,parse_addr,parse_header,ip4re
from Milter.config import MilterConfigParser

from fnmatch import fnmatchcase
from email.Utils import getaddresses,parseaddr

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

# Sometimes, MTAs reply to our DSN.  We recognize this type of reply/DSN
# and check for the original recipient SRS encoded in Message-ID.
# If found, we blacklist that recipient.
subjpats = (
 r'^failure notice',
 r'^subjectbounce',
 r'^returned mail',
 r'^undeliver',
 r'^delivery\b.*\bfail',
 r'^delivery problem',
 r'\bnot\bbe\bdelivered',
 r'\buser unknown\b',
 r'^failed',
 r'^echec de distribution',
 r'^fallo en la entrega',
 r'\bfehlgeschlagen\b'
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
mail_archive = None
_archive_lock = None
blind_wiretap = True
check_user = {}
block_forward = {}
hide_path = ()
log_headers = False
block_chinese = False
case_sensitive_localpart = False
spam_words = ()
porn_words = ()
banned_exts = mime.extlist.split(',')
scan_zip = False
scan_html = True
scan_rfc822 = True
internal_connect = ()
trusted_relay = ()
private_relay = ()
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
dspam_internal = True   # True if internal mail should be dspammed
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
  gossip_node = Gossip('gossip4.db',1000)

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
    'dspam_internal': 'yes',
    'case_sensitive_localpart': 'no'
  })
  cp.read(list)

  # milter section
  tempfile.tempdir = cp.get('milter','tempdir')
  global socketname, timeout, check_user, log_headers
  global internal_connect, internal_domains, trusted_relay, hello_blacklist
  global case_sensitive_localpart, private_relay
  socketname = cp.get('milter','socket')
  timeout = cp.getint('milter','timeout')
  check_user = cp.getaddrset('milter','check_user')
  log_headers = cp.getboolean('milter','log_headers')
  internal_connect = cp.getlist('milter','internal_connect')
  internal_domains = cp.getlist('milter','internal_domains')
  trusted_relay = cp.getlist('milter','trusted_relay')
  private_relay = cp.getlist('milter','private_relay')
  hello_blacklist = cp.getlist('milter','hello_blacklist')
  case_sensitive_localpart = cp.getboolean('milter','case_sensitive_localpart')

  # defang section
  global scan_rfc822, scan_html, block_chinese, scan_zip, block_forward
  global banned_exts, porn_words, spam_words
  if cp.has_section('defang'):
    section = 'defang'
    # for backward compatibility,
    # banned extensions defaults to empty only when defang section exists
    banned_exts = cp.getlist(section,'banned_exts')
  else: # use milter section if no defang section for compatibility
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
  global blind_wiretap,wiretap_users,wiretap_dest,discard_users,mail_archive
  blind_wiretap = cp.getboolean('wiretap','blind')
  wiretap_users = cp.getaddrset('wiretap','users')
  discard_users = cp.getaddrset('wiretap','discard')
  wiretap_dest = cp.getdefault('wiretap','dest')
  if wiretap_dest: wiretap_dest = '<%s>' % wiretap_dest
  mail_archive = cp.getdefault('wiretap','archive')

  global smart_alias
  for sa,v in [
      (k,cp.get('wiretap',k)) for k in cp.getlist('wiretap','smart_alias')
    ] + (cp.has_section('smart_alias') and cp.items('smart_alias',True) or []):
    print sa,v
    sm = [q.strip() for q in v.split(',')]
    if len(sm) < 2:
      milter_log.warning('malformed smart alias: %s',sa)
      continue
    if len(sm) == 2: sm.append(sa)
    if case_sensitive_localpart:
      key = (sm[0],sm[1])
    else:
      key = (sm[0].lower(),sm[1].lower())
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
      srs_domain.update(cp.getlist('srs','srs'))
    else:
      srs_domain = set(cp.getlist('srs','srs'))
    srs_domain.update(cp.getlist('srs','sign'))
    srs_domain.add(cp.getdefault('srs','fwdomain'))
    banned_users = cp.getlist('srs','banned_users')

def findsrs(fp):
  lastln = None
  for ln in fp:
    if lastln:
      if ln[0].isspace() and ln[0] != '\n':
        lastln += ln
        continue
      try:
        name,val = lastln.rstrip().split(None,1)
        pos = val.find('<SRS')
        if pos >= 0:
          return srs.reverse(val[pos+1:-1])
      except: continue
    lnl = ln.lower()
    if lnl.startswith('action:'):
      if lnl.split()[-1] != 'failed': break
    for k in ('message-id:','x-mailer:','sender:','references:'):
      if lnl.startswith(k):
        lastln = ln
        break

class SPFPolicy(object):
  "Get SPF policy by result from sendmail style access file."
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

from Milter.cache import AddrCache

cbv_cache = AddrCache(renew=7)
cbv_cache.load('send_dsn.log',age=30)
auto_whitelist = AddrCache(renew=30)
auto_whitelist.load('auto_whitelist.log',age=120)
blacklist = AddrCache(renew=30)
blacklist.load('blacklist.log',age=60)

class bmsMilter(Milter.Milter):
  """Milter to replace attachments poisonous to Windows with a WARNING message,
     check SPF, and other anti-forgery features, and implement wiretapping
     and smart alias redirection."""

  def log(self,*msg):
    milter_log.info('[%d] %s',self.id,' '.join([str(m) for m in msg]))

  def __init__(self):
    self.tempname = None
    self.mailfrom = None        # sender in SMTP form
    self.canon_from = None      # sender in end user form
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
      if case_sensitive_localpart:
        t = parse_addr(to)
      else:
        t = parse_addr(to.lower())
      if len(t) == 2:
        ct = '@'.join(t)
      else:
        ct = t[0]
      if case_sensitive_localpart:
        cf = self.canon_from
      else:
        cf = self.canon_from.lower()
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
    if not (self.internal_connection or self.trusted_relay)     \
        and self.connectip and spf:
      rc = self.check_spf()
      if rc != Milter.CONTINUE: return rc
    else:
      rc = Milter.CONTINUE
    # FIXME: parse Received-SPF from trusted_relay for SPF result
    res = self.spf and self.spf_guess
    hres = self.spf and self.spf_helo
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
    else:
      global gossip
      if gossip and domain and rc == Milter.CONTINUE \
          and not (self.internal_connection or self.trusted_relay):
        if self.spf and self.spf.result == 'pass':
          qual = 'SPF'
        elif res == 'pass':
          qual = 'GUESS'
        elif hres == 'pass':
          qual = 'HELO'
          domain = self.spf.h
        elif self.missing_ptr and self.spf.result == 'none':
          qual = 'IP'
          domain = self.connectip
        else:
          qual = self.connectip
        try:
          umis = gossip.umis(domain+qual,self.id+time.time())
          res,hdr,val = gossip_node.query(umis,domain,qual,1)
          self.add_header(hdr,val)
          a = val.split(',')
          self.reputation = int(a[-2])
          self.confidence = int(a[-1])
          self.umis = umis
        except:
          gossip = None
          raise
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
      self.cbv_needed = (q,res) # report SPF syntax error to sender
      res,code,txt = q.perm_error.ext   # extended (lax processing) result
      txt = 'EXT: ' + txt
    p = SPFPolicy(q.s)
    hres = None
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
      else:
        hres,hcode,htxt = res,code,txt
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
        if res != 'pass' and hres == 'pass' and spf.domainmatch([q.h],q.o):
          res = 'pass'  # get a guessed pass for valid matching HELO 
      if self.missing_ptr and ores == 'none' and res != 'pass' \
                and hres != 'pass':
        # this bad boy has no credentials whatsoever
        policy = p.getNonePolicy()
        if policy == 'CBV':
          if self.mailfrom != '<>':
            self.cbv_needed = (q,ores)  # accept, but inform sender via DSN
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
      if policy == 'CBV':
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
      if policy == 'CBV':
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
      if policy == 'CBV':
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
      if policy == 'CBV':
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
    if hres and q.h != q.o:
      self.add_header('X-Hello-SPF',hres,0)
    self.spf_guess = res
    self.spf_helo = hres
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
      self.log('REJECT: RCPT TO:',to,str)
      return Milter.REJECT
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
          self.dspam = False    # verified as reply to mail we sent
          self.blacklist = False
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

      if not self.internal_connection and domain in private_relay:
        self.log('REJECT: RELAY:',to)
	self.setreply('550','5.7.1','Unauthorized relay for %s' % domain)
        return Milter.REJECT

      # non DSN mail to SRS address will bounce due to invalid local part
      canon_to = '@'.join(t)
      self.recipients.append(canon_to)
      # FIXME: use newaddr to check rcpt
      users = check_user.get(domain)
      if self.discard:
        self.del_recipient(to)
      # don't check userlist if signed MFROM for now
      userl = user.lower()
      if users and not newaddr and not userl in users:
        self.log('REJECT: RCPT TO:',to)
        return Milter.REJECT
      # FIXME: should dspam_exempt be case insensitive?
      if user in block_forward.get(domain,()):
        self.forward = False
      exempt_users = dspam_exempt.get(domain,())
      if user in exempt_users or '' in exempt_users:
        if self.blacklist:
          self.log('REJECT: BLACKLISTED')
          self.setreply('550','5.7.1','Sending domain has been blacklisted')
          return Milter.REJECT
        self.dspam = False
      if userl != 'postmaster' and self.umis    \
        and self.reputation < -50 and self.confidence > 1:
        self.log('REJECT: REPUTATION')
        self.setreply('550','5.7.1','Your domain has been sending mostly spam')
        return Milter.REJECT

      if domain in hide_path:
        self.hidepath = True
      if not domain in dspam_reject:
        self.reject_spam = False
    self.smart_alias(to)
    # get recipient after virtusertable aliasing
    rcpt = self.getsymval("{rcpt_addr}")
    self.log("rcpt-addr",rcpt);
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
        if refaildsn.search(lval):
          self.delayed_failure = val.strip()
          # if confirmed by finding our signed Message-ID, 
          # original sender (encoded in Message-ID) is blacklisted

    elif lname == 'from':
      name,email = parseaddr(val)
      if email.lower().startswith('postmaster@'):
        # Yes, if From header comes last, this might not help much.
        # But this is a heuristic - if MTAs would send proper DSNs in
        # the first place, none of this would be needed.
        self.is_bounce = True
      
    # check for invalid message id
    elif lname == 'message-id' and len(val) < 4:
      self.log('REJECT: %s: %s' % (name,val))
      return Milter.REJECT

    # check for common bulk mailers
    elif lname == 'x-mailer':
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
      if rc != Milter.CONTINUE:
        if gossip and self.umis:
          gossip_node.feedback(self.umis,1)
        return rc
    elif self.whitelist_sender and lname == 'subject':
        # check for AutoReplys
        vl = val.lower()
        if vl.startswith('read:')       \
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
      self.fp.write("%s: %s\n" % (name,val))    # add header to buffer
    return Milter.CONTINUE

  def eoh(self):
    if not self.fp: return Milter.TEMPFAIL      # not seen by envfrom
    if not self.data_allowed:
      return self.forged_bounce()
    for name,val,idx in self.new_headers:
      self.fp.write("%s: %s\n" % (name,val))    # add new headers to buffer
    self.fp.write("\n")                         # terminate headers
    if not self.internal_connection:
      msg = None        # parse headers only if needed
      if not self.delayed_failure:
        self.fp.seek(0)
        msg = email.message_from_file(self.fp)
        if msg.get_param('report-type','').lower() == 'delivery-status':
          self.is_bounce = True
          self.delayed_failure = msg.get('subject','DSN')
      # log when neither sender nor from domains matches mail from domain
      if supply_sender and self.mailfrom != '<>':
        if not msg:
          self.fp.seek(0)
          msg = email.message_from_file(self.fp)
        mf_domain = self.canon_from.split('@')[-1]
        for rn,hf in getaddresses(msg.get_all('from',[])
                + msg.get_all('sender',[])):
          t = parse_addr(hf)
          if len(t) == 2:
            hd = t[1].lower()
            if hd == mf_domain or mf_domain.endswith('.'+hd): break
        else:
          for f in msg.get_all('from',[]):
            self.log(f)
          sender = msg.get_all('sender')
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
    self.fp.write(headers)      # IOError (e.g. disk full) causes TEMPFAIL
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

  def body(self,chunk):         # copy body to temp file
    if self.fp:
      self.fp.write(chunk)      # IOError causes TEMPFAIL in milter
      self.bodysize += len(chunk)
    return Milter.CONTINUE

  def _headerChange(self,msg,name,value):
    if value:   # add header
      self.addheader(name,value)
    else:       # delete all headers with name
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
      self.log("DISCARD RCPT: %s" % rcpt)       # log discarded rcpt
      self.delrcpt(rcpt)
    for rcpt in redirect_list:
      if rcpt in discard_list: continue
      self.log("APPEND RCPT: %s" % rcpt)        # log appended rcpt
      self.addrcpt(rcpt)
      if not blind_wiretap:
        self.addheader('Cc',rcpt)

  # 
  def gossip_header(self):
    "Set UMIS from GOSSiP header."
    msg = email.message_from_file(self.fp)
    gh = msg.get('x-gossip')
    if gh:
      self.log('X-GOSSiP:',gh)
      self.umis,_ = gh.split(',',1)

  # check spaminess for recipients in dictionary groups
  # if there are multiple users getting dspammed, then
  # a signature tag for each is added to the message.

  # FIXME: quarantine messages rejected via fixed patterns above
  #        this will give a fast start to stats

  def check_spam(self):
    "return True/False if self.fp, else return Milter.REJECT/TEMPFAIL/etc"
    self.screened = False
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
                self.log("SPAM: %s" % sender)   # log user for SPAM
                ds.add_spam(sender,txt)
                txt = None
                self.fp.seek(0)
                self.gossip_header()
                self.fp = None
                return Milter.DISCARD
            elif user == 'falsepositive' and self.internal_connection:
              sender = dspam_users.get(self.canon_from)
              if sender:
                self.log("FP: %s" % sender)     # log user for FP
                txt = ds.false_positive(sender,txt)
                self.fp = StringIO.StringIO(txt)
                self.gossip_header()
                self.delrcpt('<%s>' % rcpt)
                self.recipients = None
                self.rejectvirus = False
                return True
            elif not self.internal_connection or dspam_internal:
              if len(txt) > dspam_sizelimit:
                self.log("Large message:",len(txt))
                return False
              if user == 'honeypot' and Dspam.VERSION >= '1.1.9':
                keep = False    # keep honeypot mail
                self.fp = None
                if len(self.recipients) > 1:
                  self.log("HONEYPOT:",rcpt,'SCREENED')
                  if self.whitelist:
                    # don't train when recipients includes honeypot
                    return False
                  if self.spf and self.mailfrom != '<>':
                    # check that sender accepts quarantine DSN
                    msg = mime.message_from_file(StringIO.StringIO(txt))
                    rc = self.send_dsn(self.spf,msg,'quarantine')
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
          rc = self.send_dsn(self.spf,msg,'quarantine')
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
        self.setreply('550','5.7.1', 'Sender email local blacklist')
        return Milter.REJECT
      elif self.whitelist and ds.totals[1] < 1000:
        self.log("TRAIN:",screener,'X-Dspam-Score: %f' % ds.probability)
        # user can't correct anyway if really spam, so discard tag
        ds.check_spam(screener,txt,self.recipients,
                force_result=dspam.DSR_ISINNOCENT)
        return False
      # log spam score for screened messages
      self.add_header("X-DSpam-Score",'%f' % ds.probability)
      self.screened = True
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
      return Milter.ACCEPT      # no message collected - so no eom processing

    if self.is_bounce and len(self.recipients) > 1:
      self.log("REJECT: DSN to multiple recipients")
      self.setreply('550','5.7.1', 'DSN to multiple recipients')
      return Milter.REJECT

    try:
      # check for delayed bounce
      if self.delayed_failure:
        self.fp.seek(0)
        sender = findsrs(self.fp)
        if sender:
          cbv_cache[sender] = 550,self.delayed_failure
	  # make blacklisting persistent, since delayed DSNs are expensive
	  blacklist[sender] = None
          try:
            # save message for debugging
            fname = tempfile.mktemp(".dsn")
            os.rename(self.tempname,fname)
          except:
            fname = self.tempname
          self.tempname = None
          self.log('BLACKLIST:',sender,fname)
          return Milter.DISCARD


      # analyze external mail for spam
      spam_checked = self.check_spam()  # tag or quarantine for spam
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
    except:     # milter crashed trying to analyze mail
      exc_type,exc_value = sys.exc_info()[0:2]
      if dspam_userdir and exc_type == dspam.error:
        if not exc_value.strerror:
          exc_value.strerror = exc_value.args[0]
        if exc_value.strerror == 'Lock failed':
          milter_log.warn("LOCK: BUSY") # log filename
          self.setreply('450','4.2.0',
                'Too busy discarding spam.  Please try again later.')
          return Milter.TEMPFAIL
      fname = tempfile.mktemp(".fail")  # save message that caused crash
      os.rename(self.tempname,fname)
      self.tempname = None
      if exc_type == email.Errors.BoundaryError:
        milter_log.warn("MALFORMED: %s",fname)  # log filename
        if self.internal_connection:
          # accept anyway for now
          return Milter.ACCEPT
        self.setreply('554','5.7.7',
                'Boundary error in your message, are you a spammer?')
        return Milter.REJECT
      if exc_type == email.Errors.HeaderParseError:
        milter_log.warn("MALFORMED: %s",fname)  # log filename
        self.setreply('554','5.7.7',
                'Header parse error in your message, are you a spammer?')
        return Milter.REJECT
      milter_log.error("FAIL: %s",fname)        # log filename
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
        self.addheader(name,val)        # older sendmail can't insheader

    if self.cbv_needed:
      q,res = self.cbv_needed
      if res == 'softfail':
        template_name = 'softfail'
      elif res in ('fail','deny'):
        template_name = 'fail'
      elif res in ('unknown','permerror'):
        template_name = 'permerror'
      elif res == 'neutral':
        template_name = 'neutral'
      else:
        template_name = 'strike3'
      rc = self.send_dsn(q,msg,template_name)
      self.cbv_needed = None
      if rc == Milter.REJECT:
        # Do not feedback here, because feedback should only occur
        # for messages that have gone to DATA.  Reputation lets us
        # reject before DATA for persistent spam domains, saving
        # cycles and bandwidth.

        # Do feedback here, because CBV costs quite a bit more than
        # simply rejecting before DATA.  Bad reputation will acrue to
        # the IP or HELO, since we won't get here for validated MAILFROM.
        #       See Proverbs 26:4,5
        if gossip and self.umis:
          gossip_node.feedback(self.umis,1)
        self.train_spam()
        return Milter.REJECT
      if rc != Milter.CONTINUE:
        return rc

    if mail_archive:
      global _archive_lock
      if not _archive_lock:
        import thread
        _archive_lock = thread.allocate_lock()
      _archive_lock.acquire()
      try:
        fin = open(self.tempname,'r')
        fout = open(mail_archive,'a')
        shutil.copyfileobj(fin,fout,8192)
      finally:
        _archive_lock.release()
        fin.close()
        fout.close()
      
    if not defanged and not spam_checked:
      if gossip and self.umis and self.screened:
        gossip_node.feedback(self.umis,0)
      os.remove(self.tempname)
      self.tempname = None      # prevent re-removal
      self.log("eom")
      return rc                 # no modified attachments

    # Body modified, copy modified message to a temp file 
    if defanged:
      if self.rejectvirus and not self.hidepath:
        self.log("REJECT virus from",self.mailfrom)
        self.setreply('550','5.7.1','Attachment type not allowed.',
                'You attempted to send an attachment with a banned extension.')
        self.tempname = None
        return Milter.REJECT
      self.log("Temp file:",self.tempname)
      self.tempname = None      # prevent removal of original message copy
    out = tempfile.TemporaryFile()
    try:
      msg.dump(out)
      out.seek(0)
      # Since we wrote headers with '\n' (no CR),
      # the following header/body split should always work.
      msg = out.read().split('\n\n',1)[-1]
      self.replacebody(msg)     # feed modified message to sendmail
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
      fname = template_name+'.txt'
      try:
        template = file(template_name+'.txt').read()
        self.log('CBV:',sender,'Using:',fname)
      except IOError:
        template = None
        self.log('CBV:',sender,'PLAIN')
      m = dsn.create_msg(q,self.recipients,msg,template)
      if m:
        if srs:
          # Add SRS coded sender to various headers.  When (incorrectly)
          # replying to our DSN, any of these which are preserved
          # allow us to track the source.
          msgid = srs.forward(sender,self.receiver)
          m.add_header('Message-Id','<%s>'%msgid)
          if 'x-mailer' in m:
            m.replace_header('x-mailer','"%s" <%s>' % (m['x-mailer'],msgid))
          else:
            m.add_header('X-Mailer','"Python Milter" <%s>'%msgid)
          m.add_header('Sender','"Python Milter" <%s>'%msgid)
        m = m.as_string()
        print >>open(template_name+'.last_dsn','w'),m
      # if missing template, do plain CBV
      res = dsn.send_dsn(sender,self.receiver,m,timeout=timeout)
    if res:
      desc = "CBV: %d %s" % res[:2]
      if 400 <= res[0] < 500:
        self.log('TEMPFAIL:',desc)
        self.setreply('450','4.2.0',*desc.splitlines())
        return Milter.TEMPFAIL
      cbv_cache[sender] = res
      self.log('REJECT:',desc)
      self.setreply('550','5.7.1',*desc.splitlines())
      return Milter.REJECT
    cbv_cache[sender] = res
    return Milter.CONTINUE

  def close(self):
    if self.tempname:
      os.remove(self.tempname)  # remove in case session aborted
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
  socket.setdefaulttimeout(60)
  milter_log.info("bms milter startup")
  Milter.runmilter("pythonfilter",socketname,timeout)
  milter_log.info("bms milter shutdown")

if __name__ == "__main__":
  read_config(["/etc/mail/pymilter.cfg","milter.cfg"])
  if dspam_dict:
    import dspam        # low level spam check
  if dspam_userdir:
    import dspam
    import Dspam        # high level spam check
    try:
      dspam_version = Dspam.VERSION
    except:
      dspam_version = '1.1.4'
    assert dspam_version >= '1.1.5'
  main()
