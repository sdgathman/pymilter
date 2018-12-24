## @package Milter.testctx
# A test framework for milters that replaces milterContext rather
# than Milter.Base.  Since miltermodule.c doesn't currently export
# a way to query callbacks set (and we might want to run without 
# loading milter), we assume the callbacks set by Milter.runmilter().

from __future__ import print_function
from socket import AF_INET,AF_INET6
import time
import mime
try:
  from io import BytesIO
except:
  from StringIO import StringIO as BytesIO
import Milter
from Milter import utils
import mime

## Milter context for unit testing %milter applications.
# A substitute for milter.milterContext that can be passed to
# Milter.Base._setctx().
# @since 1.0.3
class TestCtx(object):
  default_opts = [Milter.CURR_ACTS,0x1fffff,0,0]
  def __init__(self,logfile='test/milter.log'):
    ## Usually the Milter application derived from Milter.Base
    self._priv = None
    ## List of recipients deleted
    self._delrcpt = []
    ## List of recipients added
    self._addrcpt = []
    ## Macros defined
    self._macros = { }
    ## Reply codes and messages set by the %milter
    self._reply = None
    ## The macros returned by protocol stage
    self._symlist = [ None, None, None, None, None, None, None ]
    ## The message body.
    self._body = None
    ## True if the %milter replaced the message body.
    self._bodyreplaced = False
    ## True if the %milter changed any headers.
    self._headerschanged = False
    ## The rfc822 message object for the current email being fed to the %milter.
    self._msg = None
    ## The MAIL FROM for the current email being fed to the %milter
    self._sender = None
    ## True if the %milter changed the envelope from.
    self._envfromchanged = False
    ## List of recipients added
    self._addrcpt = []
    ## Negotiated options
    self._opts = TestCtx.default_opts
    ## Last activity
    self._activity = time.time()

  def getpriv(self):
    return self._priv

  def setpriv(self,priv):
    self._priv = priv

  def getsymval(self,name):
    stage = self._stage
    if stage >= 0:
      try:
        s = name.encode('utf8')
      except: pass
      syms = self._symlist[stage]
      if syms is not None and s not in syms:
        return None
    return self._macros.get(name,None)

  def _setsymval(self,name,val):
    self._macros[name] = val

  def setreply(self,rcode,xcode,*msg):
    self._reply = (rcode,xcode) + msg

  def setsymlist(self,stage,macros):
    if self._stage != -1:
      raise RuntimeError("setsymlist may only be called from negotiate")
    # Records which macros are available to getsymval()
    m = macros
    try:
      m = m.encode('utf8')
    except: pass
    try:
      m = m.split(b' ')
    except: pass
    if len(m) > 5:
      raise ValueError('setsymlist limited to 5 macros by MTA')
    if self._symlist[stage] is not None:
      raise ValueError('setsymlist already called for stage:'+stage)
    if not m:
      raise ValueError('setsymlist with empty list for stage:'+stage)
    self._symlist[stage] = set(m)

  def addheader(self,field,value,idx):
    if not self._body:
      raise IOError("addheader not called from eom()")
    self._msg[field] = value
    self._headerschanged = True

  def chgheader(self,field,idx,value):
    if not self._body:
      raise IOError("chgheader not called from eom()")
    if value == '':
      del self._msg[field]
    else:
      self._msg[field] = value
    self._headerschanged = True
 
  def addrcpt(self,rcpt,params):
    if not self._body:
      raise IOError("addrcpt not called from eom()")
    self._addrcpt.append((rcpt,params))

  def delrcpt(self,rcpt):
    if not self._body:
      raise IOError("delrcpt not called from eom()")
    self._delrcpt.append(rcpt)

  def replacebody(self,chunk):
    if self._body:
      self._body.write(chunk)
      self._bodyreplaced = True
    else:
      raise IOError("replacebody not called from eom()")

  def chgfrom(self,sender,params=None):
    if not self._body:
      raise IOError("chgfrom not called from eom()")
    self._envfromchanged = True
    self._sender = sender

  def quarantine(self,reason):
    raise NotImplemented

  ## Reset activity timer.
  def progress(self):
    self._activity = time.time()

  def _abort(self):
    "What Milter sets for abort_callback"
    self._priv.abort()
    self._close()

  def _close(self):
    Milter.close_callback(self)

  def _negotiate(self):
    self._body = None
    self._bodyreplaced = False
    self._priv = None
    self._opts = TestCtx.default_opts
    self._stage = -1
    rc = Milter.negotiate_callback(self,self._opts)
    if rc == Milter.ALL_OPTS:
      self._opts = TestCtx.default_opts
    elif rc != Milter.CONTINUE:
      self._abort()
      self._close()
    self._protocol = self._opts[1]
    return rc

  def _connect(self,host='localhost',helo='spamrelay',ip='1.2.3.4'):
    rc = self._negotiate()
    # FIXME: what if not CONTINUE or ALL_OPTS?
    if self._protocol & Milter.P_NOCONNECT:
      return Milter.CONTINUE
    if utils.ip4re.match(ip):
      af = AF_INET
    elif utils.ip6re.match(ip):
      af = AF_INET6
    else:
      raise ValueError('TestCtx.connect: invalid ip address: '+ip)
    self._stage = Milter.M_CONNECT
    rc = Milter.connect_callback(self,host,af,ip)
    self._stage = None
    if rc != Milter.CONTINUE:
      self._close()
      return rc
    return self._helo(helo)

  def _helo(self,helo):
    if self._protocol & Milter.P_NOHELO:
      return Milter.CONTINUE
    self._stage = Milter.M_HELO
    rc = self._priv.hello(helo)
    self._stage = None
    if rc != Milter.CONTINUE:
      self._close()
    return rc

  def _envfrom(self,*s):
    self._sender = s[0]
    if self._protocol & Milter.P_NOMAIL:
      return Milter.CONTINUE
    self._stage = Milter.M_ENVFROM
    rc = self._priv.envfrom(*s)
    self._stage = None
    return rc

  def _envrcpt(self,s):
    if self._protocol & Milter.P_NORCPT:
      return Milter.CONTINUE
    self._stage = Milter.M_ENVRCPT
    rc = self._priv.envrcpt(s)
    self._stage = None
    return rc

  def _data(self):
    if self._protocol & Milter.P_NODATA:
      return Milter.CONTINUE
    self._stage = Milter.M_DATA
    rc = self._priv.data()
    self._stage = None
    return rc

  def _header(self,fld,val):
    return self._priv.header(fld,val)

  def _eoh(self):
    if self._protocol & Milter.P_NOEOH:
      return Milter.CONTINUE
    self._stage = Milter.M_EOH
    rc = self._priv.eoh()
    self._stage = None
    return rc

  def _feed_body(self,bfp):
    if self._protocol & Milter.P_NOBODY:
      return Milter.CONTINUE
    while True:
      buf = bfp.read(8192)
      if len(buf) == 0: break
      rc = self._priv.body(buf)
      if rc != Milter.CONTINUE: return rc
    return Milter.CONTINUE

  def _eom(self):
    self._body = BytesIO()
    self._stage = Milter.M_EOM
    rc = self._priv.eom()
    self._stage = None
    return rc

  ## Feed a file like object to the ctx.  Calls the callbacks in
  # the same sequence as libmilter.
  # @param fp the file with rfc2822 message stream
  # @param sender the MAIL FROM
  # @param rcpt RCPT TO - additional recipients may follow
  def _feedFile(self,fp,sender="spam@adv.com",rcpt="victim@lamb.com",*rcpts):
    self._body = None
    self._bodyreplaced = False
    self._headerschanged = False
    self._reply = None
    msg = mime.message_from_file(fp)
    self._msg = msg
    # envfrom
    rc = self._envfrom('<%s>'%sender)
    if rc != Milter.CONTINUE: return rc
    # envrcpt
    for rcpt in (rcpt,) + rcpts:
      rc = self._envrcpt('<%s>'%rcpt)
      if rc != Milter.CONTINUE: return rc
    # data
    rc = self._data()
    if rc != Milter.CONTINUE: return rc
    # header
    for h,val in msg.items():
      rc = self._header(h,val)
      if rc != Milter.CONTINUE: return rc
    # eoh
    rc = self._eoh()
    if rc != Milter.CONTINUE: return rc
    # body
    header,body = msg.as_bytes().split(b'\n\n',1)
    rc = self._feed_body(BytesIO(body))
    if rc != Milter.CONTINUE: return rc
    rc = self._eom()
    if self._bodyreplaced:
      body = self._body.getvalue()
    self._body = BytesIO()
    self._body.write(header)
    self._body.write(b'\n\n')
    self._body.write(body)
    return rc

  ## Feed an email contained in a file to the %milter.
  # This is a convenience method that invokes @link #feedFile feedFile @endlink.
  # @param sender MAIL FROM
  # @param rcpts RCPT TO, multiple recipients may be supplied
  def _feedMsg(self,fname,sender="spam@adv.com",*rcpts):
    with open('test/'+fname,'rb') as fp:
      return self._feedFile(fp,sender,*rcpts)
