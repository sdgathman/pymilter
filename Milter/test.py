## @package Milter.test
# A test framework for milters

import rfc822
import StringIO
import Milter

## 
#
class TestBase(object):

  _protocol = 0
  def __init__(self):
    self.logfp = open("test/milter.log","a")
    self._delrcpt = []	# record deleted rcpts for testing
    self._addrcpt = []	# record added rcpts for testing
    self._macros = { }

  def log(self,*msg):
    for i in msg: print >>self.logfp, i,
    print >>self.logfp

  def setsymval(self,name,val,step=None):
    self._macros[name] = val
    
  def getsymval(self,name):
    return self._macros.get(name,'')

  def replacebody(self,chunk):
    if self._body:
      self._body.write(chunk)
      self.bodyreplaced = True
    else:
      raise IOError,"replacebody not called from eom()"

  # FIXME: rfc822 indexing does not really reflect the way chg/add header
  # work for a milter
  def chgheader(self,field,idx,value):
    if not self._body:
      raise IOError,"chgheader not called from eom()"
    self.log('chgheader: %s[%d]=%s' % (field,idx,value))
    if value == '':
      del self._msg[field]
    else:
      self._msg[field] = value
    self.headerschanged = True

  def addheader(self,field,value,idx=-1):
    if not self._body:
      raise IOError,"addheader not called from eom()"
    self.log('addheader: %s=%s' % (field,value))
    self._msg[field] = value
    self.headerschanged = True

  def delrcpt(self,rcpt):
    if not self._body:
      raise IOError,"delrcpt not called from eom()"
    self._delrcpt.append(rcpt)

  def addrcpt(self,rcpt):
    if not self._body:
      raise IOError,"addrcpt not called from eom()"
    self._addrcpt.append(rcpt)

  def setreply(self,rcode,xcode,msg):
    self.reply = (rcode,xcode,msg)

  def feedFile(self,fp,sender="spam@adv.com",rcpt="victim@lamb.com"):
    self._body = None
    self.bodyreplaced = False
    self.headerschanged = False
    self.reply = None
    msg = rfc822.Message(fp)
    rc = self.envfrom('<%s>'%sender)
    if rc != Milter.CONTINUE: return rc
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
    if self.bodyreplaced:
      body = self._body.getvalue()
    else:
      msg.rewindbody()
      body = msg.fp.read()
    self._body = StringIO.StringIO()
    self._body.writelines(msg.headers)
    self._body.write('\n')
    self._body.write(body)
    return rc

  def feedMsg(self,fname,sender="spam@adv.com",rcpt="victim@lamb.com"):
    fp = open('test/'+fname,'r')
    rc = self.feedFile(fp,sender,rcpt)
    fp.close()
    return rc

  def connect(self,host='localhost',helo='spamrelay',ip='1.2.3.4'):
    self._body = None
    self.bodyreplaced = False
    rc =  super(TestBase,self).connect(host,1,(ip,1234)) 
    if rc != Milter.CONTINUE and rc != Milter.ACCEPT:
      self.close()
      return rc
    rc = self.hello(helo)
    if rc != Milter.CONTINUE:
      self.close()
    return rc

