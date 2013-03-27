## @package Milter.test
# A test framework for milters

import rfc822
import StringIO
import Milter

Milter.NOREPLY = Milter.CONTINUE

## Test mixin for unit testing %milter applications.
# This mixin overrides many Milter.MilterBase methods
# with stub versions that simply record what was done.
# @since 0.9.8
class TestBase(object):

  def __init__(self,logfile='test/milter.log'):
    self._protocol = 0
    self.logfp = open(logfile,"a")
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
    ## Reply codes and messages set by the %milter
    self._reply = None
    ## The rfc822 message object for the current email being fed to the %milter.
    self._msg = None
    self._symlist = [ None, None, None, None, None, None, None ]

  def log(self,*msg):
    for i in msg: print >>self.logfp, i,
    print >>self.logfp

  ## Set a macro value.
  # These are retrieved by the %milter with getsymval.
  # @param name the macro name, as passed to getsymval
  # @param val the macro value
  def setsymval(self,name,val):
    self._macros[name] = val
    
  def getsymval(self,name):
    # FIXME: track stage, and use _symlist
    return self._macros.get(name,'')

  def replacebody(self,chunk):
    if self._body:
      self._body.write(chunk)
      self._bodyreplaced = True
    else:
      raise IOError,"replacebody not called from eom()"

  # FIXME: rfc822 indexing does not really reflect the way chg/add header
  # work for a %milter
  def chgheader(self,field,idx,value):
    if not self._body:
      raise IOError,"chgheader not called from eom()"
    self.log('chgheader: %s[%d]=%s' % (field,idx,value))
    if value == '':
      del self._msg[field]
    else:
      self._msg[field] = value
    self._headerschanged = True

  def addheader(self,field,value,idx=-1):
    if not self._body:
      raise IOError,"addheader not called from eom()"
    self.log('addheader: %s=%s' % (field,value))
    self._msg[field] = value
    self._headerschanged = True

  def delrcpt(self,rcpt):
    if not self._body:
      raise IOError,"delrcpt not called from eom()"
    self._delrcpt.append(rcpt)

  def addrcpt(self,rcpt):
    if not self._body:
      raise IOError,"addrcpt not called from eom()"
    self._addrcpt.append(rcpt)

  ## Save the reply codes and messages in self._reply.
  def setreply(self,rcode,xcode,*msg):
    self._reply = (rcode,xcode) + msg

  def setsymlist(self,stage,macros):
    if not self._actions & SETSYMLIST: raise DisabledAction("SETSYMLIST")
    # not used yet, but just for grins we save the data
    a = []
    for m in macros:
      try:
        m = m.encode('utf8')
      except: pass
      try:
        m = m.split(' ')
      except: pass
      a += m
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
    msg = rfc822.Message(fp)
    rc = self.envfrom('<%s>'%sender)
    if rc != Milter.CONTINUE: return rc
    for rcpt in (rcpt,) + rcpts:
      rc = self.envrcpt('<%s>'%rcpt)
      if rc != Milter.CONTINUE: return rc
    line = None
    for h in msg.headers:
      if h[:1].isspace():
        line = line + h
        continue
      if not line:
        line = h
        continue
      s = line.split(': ',1)
      if len(s) > 1: val = s[1].strip()
      else: val = ''
      rc = self.header(s[0],val)
      if rc != Milter.CONTINUE: return rc
      line = h
    if line:
      s = line.split(': ',1)
      rc = self.header(s[0],s[1])
      if rc != Milter.CONTINUE: return rc
    rc = self.eoh()
    if rc != Milter.CONTINUE: return rc
    while 1:
      buf = fp.read(8192)
      if len(buf) == 0: break
      rc = self.body(buf)
      if rc != Milter.CONTINUE: return rc
    self._msg = msg
    self._body = StringIO.StringIO()
    rc = self.eom()
    if self._bodyreplaced:
      body = self._body.getvalue()
    else:
      msg.rewindbody()
      body = msg.fp.read()
    self._body = StringIO.StringIO()
    self._body.writelines(msg.headers)
    self._body.write('\n')
    self._body.write(body)
    return rc

  ## Feed an email contained in a file to the %milter.
  # This is a convenience method that invokes @link #feedFile feedFile @endlink.
  # @param sender MAIL FROM
  # @param rcpts RCPT TO, multiple recipients may be supplied
  def feedMsg(self,fname,sender="spam@adv.com",*rcpts):
    with open('test/'+fname,'r') as fp:
      return self.feedFile(fp,sender,*rcpts)

  ## Call the connect and helo callbacks.
  # The helo callback is not called if connect does not return CONTINUE.
  # @param host the hostname passed to the connect callback
  # @param helo the hostname passed to the helo callback
  # @param ip the IP address passed to the connect callback
  def connect(self,host='localhost',helo='spamrelay',ip='1.2.3.4'):
    self._body = None
    self._bodyreplaced = False
    opts = [ Milter.CURR_ACTS,~0,0,0 ]
    rc = self.negotiate(opts)
    rc =  super(TestBase,self).connect(host,1,(ip,1234)) 
    if rc != Milter.CONTINUE:
      self.close()
      return rc
    rc = self.hello(helo)
    if rc != Milter.CONTINUE:
      self.close()
    return rc
