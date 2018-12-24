## @package Milter.test
# A test framework for milters

from __future__ import print_function
import mime
try:
  from io import BytesIO
except:
  from StringIO import StringIO as BytesIO
import Milter

Milter.NOREPLY = Milter.CONTINUE

## Test mixin for unit testing %milter applications.
# This mixin overrides many Milter.MilterBase methods
# with stub versions that simply record what was done.
# @deprecated Use Milter.test.TestCtx
# @since 0.9.8
class TestBase(object):

  def __init__(self,logfile='test/milter.log'):
    self._protocol = 0
    self.logfp = open(logfile,"a")
    ## The MAIL FROM for the current email being fed to the %milter
    self._sender = None
    ## List of recipients deleted
    self._delrcpt = []
    ## List of recipients added
    self._addrcpt = []
    ## Macros defined
    self._macros = { }
    ## The message body.
    self._body = None
    ## True if the %milter replaced the message body.
    self._bodyreplaced = False
    ## True if the %milter changed any headers.
    self._headerschanged = False
    ## True if the %milter changed the envelope from.
    self._envfromchanged = False
    ## Reply codes and messages set by the %milter
    self._reply = None
    ## The rfc822 message object for the current email being fed to the %milter.
    self._msg = None
    ## The protocol stage for macros returned
    self._stage = None
    ## The macros returned by protocol stage
    self._symlist = [ None, None, None, None, None, None, None ]

  def log(self,*msg):
    for i in msg: print(i,file=self.logfp,end=None)
    print(file=self.logfp)

  ## Set a macro value.
  # These are retrieved by the %milter with getsymval.
  # @param name the macro name, as passed to getsymval
  # @param val the macro value
  def setsymval(self,name,val):
    self._macros[name] = val
    
  def getsymval(self,name):
    stage = self._stage
    if stage >= 0:
      syms = self._symlist[stage]
      if syms is not None and name not in syms:
        return None
    return self._macros.get(name,None)

  def replacebody(self,chunk):
    if self._body:
      self._body.write(chunk)
      self._bodyreplaced = True
    else:
      raise IOError("replacebody not called from eom()")

  def chgfrom(self,sender,params=None):
    if not self._body:
      raise IOError("chgfrom not called from eom()")
    self.log('chgfrom: sender=%s' % (sender))
    self._envfromchanged = True
    self._sender = sender

  # TODO: write implement quarantine()
  def quarantine(self,reason):
    raise NotImplemented

  # TODO: measure time between milter calls
  def progress(self):
    pass

  # FIXME: rfc822 indexing does not really reflect the way chg/add header
  # work for a %milter
  def chgheader(self,field,idx,value):
    if not self._body:
      raise IOError("chgheader not called from eom()")
    self.log('chgheader: %s[%d]=%s' % (field,idx,value))
    if value == '':
      del self._msg[field]
    else:
      self._msg[field] = value
    self._headerschanged = True

  def addheader(self,field,value,idx=-1):
    if not self._body:
      raise IOError("addheader not called from eom()")
    self.log('addheader: %s=%s' % (field,value))
    self._msg[field] = value
    self._headerschanged = True

  def delrcpt(self,rcpt):
    if not self._body:
      raise IOError("delrcpt not called from eom()")
    self._delrcpt.append(rcpt)

  def addrcpt(self,rcpt):
    if not self._body:
      raise IOError("addrcpt not called from eom()")
    self._addrcpt.append(rcpt)

  ## Save the reply codes and messages in self._reply.
  def setreply(self,rcode,xcode,*msg):
    self._reply = (rcode,xcode) + msg

  def setsymlist(self,stage,macros):
    if not self._actions & Milter.SETSYMLIST:
      raise DisabledAction("SETSYMLIST")
    if self._stage != -1:
      raise RuntimeError("setsymlist may only be called from negotiate")
    # not used yet, but just for grins we save the data
    a = []
    for m in macros:
      try:
        m = m.encode('utf8')
      except: pass
      try:
        m = m.split(b' ')
      except: pass
      a += m
    if len(a) > 5:
      raise ValueError('setsymlist limited to 5 macros by MTA')
    if self._symlist[stage] is not None:
      raise ValueError('setsymlist already called for stage:'+stage)
    print('setsymlist',stage,a)
    self._symlist[stage] = set(a)

  ## Feed a file like object to the %milter.  Calls envfrom, envrcpt for
  # each recipient, header for each header field, body for each body 
  # block, and finally eom.  A return code from the %milter other than
  # CONTINUE returns immediately with that return code.
  #
  # This is a convenience method, a test could invoke the callbacks
  # in sequence on its own - and for some complex tests, this may
  # be necessary.
  # @param fp the file with rfc2822 message stream
  # @param sender the MAIL FROM
  # @param rcpt RCPT TO - additional recipients may follow
  def feedFile(self,fp,sender="spam@adv.com",rcpt="victim@lamb.com",*rcpts):
    self._body = None
    self._bodyreplaced = False
    self._headerschanged = False
    self._reply = None
    self._sender = '<%s>'%sender
    msg = mime.message_from_file(fp)
    # envfrom
    self._stage = Milter.M_ENVFROM
    rc = self.envfrom(self._sender)
    self._stage = None
    if rc != Milter.CONTINUE: return rc
    # envrcpt
    for rcpt in (rcpt,) + rcpts:
      self._stage = Milter.M_ENVRCPT
      rc = self.envrcpt('<%s>'%rcpt)
      self._stage = None
      if rc != Milter.CONTINUE: return rc
    # data
    self._stage = Milter.M_DATA
    rc = self.data()
    self._stage = None
    if rc != Milter.CONTINUE: return rc
    # header
    for h,val in msg.items():
      rc = self.header(h,val)
      if rc != Milter.CONTINUE: return rc
    # eoh
    self._stage = Milter.M_EOH
    rc = self.eoh()
    self._stage = None
    if rc != Milter.CONTINUE: return rc
    # body
    header,body = msg.as_bytes().split(b'\n\n',1)
    bfp = BytesIO(body)
    while 1:
      buf = bfp.read(8192)
      if len(buf) == 0: break
      rc = self.body(buf)
      if rc != Milter.CONTINUE: return rc
    self._msg = msg
    self._body = BytesIO()
    self._stage = Milter.M_EOM
    rc = self.eom()
    self._stage = None
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
  def feedMsg(self,fname,sender="spam@adv.com",*rcpts):
    with open('test/'+fname,'rb') as fp:
      return self.feedFile(fp,sender,*rcpts)

  ## Call the connect and helo callbacks.
  # The helo callback is not called if connect does not return CONTINUE.
  # @param host the hostname passed to the connect callback
  # @param helo the hostname passed to the helo callback
  # @param ip the IP address passed to the connect callback
  def connect(self,host='localhost',helo='spamrelay',ip='1.2.3.4'):
    self._body = None
    self._bodyreplaced = False
    self._setctx(None)
    opts = [ Milter.CURR_ACTS,~0,0,0 ]
    self._stage = -1
    rc = self.negotiate(opts)
    self._stage = Milter.M_CONNECT
    rc =  super(TestBase,self).connect(host,1,(ip,1234)) 
    if rc != Milter.CONTINUE:
      self._stage = None
      self.close()
      return rc
    self._stage = Milter.M_HELO
    rc = self.hello(helo)
    self._stage = None
    if rc != Milter.CONTINUE:
      self.close()
    return rc
