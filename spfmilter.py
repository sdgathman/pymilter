# A simple SPF milter.
# You must install pyspf for this to work.

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import os
import re
import Milter
import spf
import struct
import socket
import syslog

syslog.openlog('spfmilter',0,syslog.LOG_MAIL)

# list of trusted forwarder domains.  An SPF record for a forwarder
# domain lists IP addresses from which forwarded mail is accepted.
trusted_forwarder = []
# list of internal LAN ips.  No SPF check is done for these.
internal_connect = ['127.0.0.1','192.168.0.0/16']
# list of trusted relays.  These are typically secondary MXes, and
# no SPF check is done for these.
trusted_relay = []

socketname = "/var/run/milter/spfmiltersock"
#socketname = os.getenv("HOME") + "/pythonsock"

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

class spfMilter(Milter.Milter):
  "Milter to check SPF."

  def log(self,*msg):
    syslog.syslog('[%d] %s' % (self.id,' '.join([str(m) for m in msg])))

  def __init__(self):
    self.mailfrom = None
    self.id = Milter.uniqueID()

  # addheader can only be called from eom().  This accumulates added headers
  # which can then be applied by alter_headers()
  def add_header(self,name,val,idx=-1):
    self.new_headers.append((name,val,idx))
    self.log('%s: %s' % (name,val))

  def connect(self,hostname,unused,hostaddr):
    self.internal_connection = False
    self.trusted_relay = False
    self.hello_name = None
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
    if self.internal_connection:
      connecttype = 'INTERNAL'
    else:
      connecttype = 'EXTERNAL'
    if self.trusted_relay:
      connecttype += ' TRUSTED'
    self.log("connect from %s at %s %s" % (hostname,hostaddr,connecttype))
    return Milter.CONTINUE

  def hello(self,hostname):
    self.hello_name = hostname
    self.log("hello from %s" % hostname)
    return Milter.CONTINUE

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  def envfrom(self,f,*str):
    self.log("mail from",f,str)
    self.mailfrom = f
    self.new_headers = []
    t = parse_addr(f)
    if len(t) == 2: t[1] = t[1].lower()
    self.canon_from = '@'.join(t)
    if not (self.internal_connection or self.trusted_relay) and self.connectip:
      rc = self.check_spf()
      if rc != Milter.CONTINUE: return rc
    return Milter.CONTINUE

  def envrcpt(self,f,*str):
    return Milter.CONTINUE

  def header(self,name,hval):
    return Milter.CONTINUE

  def eoh(self):
    return Milter.CONTINUE

  def eom(self):
    for name,val,idx in self.new_headers:
      try:
	self.addheader(name,val,idx)
      except:
	self.addheader(name,val)	# older sendmail can't insheader
    return Milter.CONTINUE

  def close(self):
    return Milter.CONTINUE

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
    if res not in ('pass','temperror'):
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
      else:
        hres,hcode,htxt = res,code,txt
    else: hres = None
    if res == 'fail':
      self.log('REJECT: SPF %s %i %s' % (res,code,txt))
      self.setreply(str(code),'5.7.1',txt)
      # A proper SPF fail error message would read:
      # forger.biz [1.2.3.4] is not allowed to send mail with the domain
      # "forged.org" in the sender address.  Contact <postmaster@forged.org>.
      return Milter.REJECT
    if res == 'permerror':
      self.log('REJECT: SPF %s %i %s' % (res,code,txt))
      # latest SPF draft recommends 5.5.2 instead of 5.7.1
      self.setreply(str(code),'5.5.2',txt,
	'There is a fatal syntax error in the SPF record for %s' % q.o,
	'We cannot accept mail from %s until this is corrected.' % q.o
      )
      return Milter.REJECT
    if res == 'temperror':
      self.log('TEMPFAIL: SPF %s %i %s' % (res,code,txt))
      self.setreply(str(code),'4.3.0',txt)
      return Milter.TEMPFAIL
    self.add_header('Received-SPF',q.get_header(res,receiver),0)
    if hres and q.h != q.o:
      self.add_header('X-Hello-SPF',hres,0)
    return Milter.CONTINUE

if __name__ == "__main__":
  Milter.factory = spfMilter
  Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
  print """To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=pyspffilter
Xpyspffilter,        S=local:%s

See the sendmail README for libmilter.
sample spfmilter startup""" % socketname
  sys.stdout.flush()
  Milter.runmilter("pyspffilter",socketname,240)
  print "sample spfmilter shutdown"
