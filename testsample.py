import unittest
import Milter
import sample
import mime
import rfc822
import StringIO

class TestMilter(sample.sampleMilter):

  _protocol = 0
  def __init__(self):
    self.logfp = open("test/milter.log","a")

  def log(self,*msg):
    for i in msg: print >>self.logfp, i,
    print >>self.logfp

  def replacebody(self,chunk):
    if self._body:
      self._body.write(chunk)
      self.bodyreplaced = True
    else:
      raise IOError,"replacebody not called from eom()"

  # FIXME: rfc822 indexing does not really reflect the way chg/add header
  # work for a milter
  def chgheader(self,field,idx,value):
    self.log('chgheader: %s[%d]=%s' % (field,idx,value))
    if value == '':
      del self._msg[field]
    else:
      self._msg[field] = value
    self.headerschanged = True

  def addheader(self,field,value):
    self.log('addheader: %s=%s' % (field,value))
    self._msg[field] = value
    self.headerschanged = True

  def feedMsg(self,fname):
    self._body = None
    self.bodyreplaced = False
    self.headerschanged = 0
    fp = open('test/'+fname,'r')
    msg = rfc822.Message(fp)
    rc = self.envfrom('<spam@advertisements.com>')
    if rc != Milter.CONTINUE: return rc
    rc = self.envrcpt('<victim@lamb.com>')
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
      rc = self.header(s[0],s[1].strip())
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

  def connect(self,host='localhost'):
    self._body = None
    self.bodyreplaced = False
    rc =  sample.sampleMilter.connect(self,host,1,0) 
    if rc != Milter.CONTINUE and rc != Milter.ACCEPT:
      self.close()
      return rc
    rc = self.hello('spamrelay')
    if rc != Milter.CONTINUE:
      self.close()
    return rc

class BMSMilterTestCase(unittest.TestCase):

  def testDefang(self,fname='virus1'):
    milter = TestMilter()
    rc = milter.connect()
    self.failUnless(rc == Milter.CONTINUE)
    rc = milter.feedMsg(fname)
    self.failUnless(rc == Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus1.out","r").read())
    fp.seek(0)
    msg = mime.message_from_file(fp)
    s = msg.get_payload(1).get_payload()
    milter.log(s)
    milter.close()

  def testParse(self,fname='spam7'):
    milter = TestMilter()
    milter.connect('somehost')
    rc = milter.feedMsg(fname)
    self.failUnless(rc == Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    milter.close()

  def testDefang2(self):
    milter = TestMilter()
    milter.connect('somehost')
    rc = milter.feedMsg('samp1')
    self.failUnless(rc == Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg("virus3")
    self.failUnless(rc == Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus3.tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus3.out","r").read())
    rc = milter.feedMsg("virus6")
    self.failUnless(rc == Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    self.failUnless(milter.headerschanged,"Message headers not adjusted")
    fp = milter._body
    open("test/virus6.tstout","w").write(fp.getvalue())
    milter.close()

def suite(): return unittest.makeSuite(BMSMilterTestCase,'test')

if __name__ == '__main__':
  unittest.main()
