# A simple SPF milter.
# You must install pyspf for this to work.

# http://www.sendmail.org/doc/sendmail-current/libmilter/docs/installation.html

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2007 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import Milter
import spf
import syslog
import anydbm
from Milter.config import MilterConfigParser
from Milter.utils import iniplist,parse_addr

syslog.openlog('spfmilter',0,syslog.LOG_MAIL)

class Config(object):
  "Hold configuration options."
  pass

def read_config(list):
  "Return new config object."
  cp = MilterConfigParser()
  cp.read(list)
  if cp.has_option('milter','datadir'):
        os.chdir(cp.get('milter','datadir'))
  conf = Config()
  conf.socketname = cp.getdefault('milter','socketname', '/tmp/spfmiltersock')
  conf.miltername = cp.getdefault('milter','name','pyspffilter')
  conf.trusted_relay = cp.getlist('milter','trusted_relay')
  conf.internal_connect = cp.getlist('milter','internal_connect')
  conf.trusted_forwarder = cp.getlist('spf','trusted_relay')
  conf.access_file = cp.getdefault('spf','access_file',None)
  return conf

class SPFPolicy(object):
  "Get SPF policy by result from sendmail style access file."
  def __init__(self,sender,access_file=None):
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
  
class spfMilter(Milter.Milter):
  "Milter to check SPF.  Each connection gets its own instance."

  def log(self,*msg):
    syslog.syslog('[%d] %s' % (self.id,' '.join([str(m) for m in msg])))

  def __init__(self):
    self.mailfrom = None
    self.id = Milter.uniqueID()
    # we don't want config used to change during a connection
    self.conf = config

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
      if iniplist(ipaddr,self.conf.internal_connect):
	self.internal_connection = True
      if iniplist(ipaddr,self.conf.trusted_relay):
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
    if not self.hello_name:
      self.log('REJECT: missing HELO')
      self.setreply('550','5.7.1',"It's polite to say helo first.")
      return Milter.REJECT
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
    for tf in self.conf.trusted_forwarder:
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

    p = SPFPolicy(q.s,self.conf.access_file)

    if res == 'fail':
      policy = p.getPolicy('spf-fail:')
      if not policy or policy == 'REJECT':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	self.setreply(str(code),'5.7.1',txt)
	# A proper SPF fail error message would read:
	# forger.biz [1.2.3.4] is not allowed to send mail with the domain
	# "forged.org" in the sender address.  Contact <postmaster@forged.org>.
	return Milter.REJECT
    if res == 'softfail':
      policy = p.getPolicy('spf-softfail:')
      if policy and policy == 'REJECT':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	self.setreply(str(code),'5.7.1',txt)
	# A proper SPF fail error message would read:
	# forger.biz [1.2.3.4] is not allowed to send mail with the domain
	# "forged.org" in the sender address.  Contact <postmaster@forged.org>.
	return Milter.REJECT
    elif res == 'permerror':
      policy = p.getPolicy('spf-permerror:')
      if not policy or policy == 'REJECT':
	self.log('REJECT: SPF %s %i %s' % (res,code,txt))
	# latest SPF draft recommends 5.5.2 instead of 5.7.1
	self.setreply(str(code),'5.5.2',txt,
	  'There is a fatal syntax error in the SPF record for %s' % q.o,
	  'We cannot accept mail from %s until this is corrected.' % q.o
	)
	return Milter.REJECT
    elif res == 'temperror':
      policy = p.getPolicy('spf-temperror:')
      if not policy or policy == 'REJECT':
	self.log('TEMPFAIL: SPF %s %i %s' % (res,code,txt))
	self.setreply(str(code),'4.3.0',txt)
	return Milter.TEMPFAIL
    elif res == 'neutral' or res == 'none':
      policy = p.getPolicy('spf-neutral:')
      if policy and policy == 'REJECT':
        self.log('REJECT NEUTRAL:',q.s)
	self.setreply('550','5.7.1',
  "%s requires and SPF PASS to accept mail from %s. [http://openspf.org]"
	  % (receiver,q.s))
	return Milter.REJECT
    elif res == 'pass':
      policy = p.getPolicy('spf-pass:')
      if policy and policy == 'REJECT':
        self.log('REJECT PASS:',q.s)
	self.setreply('550','5.7.1',
		"%s has been blacklisted by %s." % (q.s,receiver))
	return Milter.REJECT
    self.add_header('Received-SPF',q.get_header(res,receiver),0)
    if hres and q.h != q.o:
      self.add_header('X-Hello-SPF',hres,0)
    return Milter.CONTINUE

if __name__ == "__main__":
  Milter.factory = spfMilter
  Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
  global config
  config = read_config(['spfmilter.cfg','/etc/mail/spfmilter.cfg'])
  miltername = config.miltername
  socketname = config.socketname
  print """To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=%s
X%s,        S=local:%s

See the sendmail README for libmilter.
sample spfmilter startup""" % (miltername,miltername,socketname)
  sys.stdout.flush()
  Milter.runmilter("pyspffilter",socketname,240)
  print "sample spfmilter shutdown"
