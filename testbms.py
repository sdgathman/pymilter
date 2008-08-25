import unittest
import doctest
import Milter
import bms
import mime
import rfc822
import StringIO
import email
import sys
#import pdb

class TestMilter(bms.bmsMilter):

  def __init__(self):
    bms.bmsMilter.__init__(self)
    self.logfp = open("test/milter.log","a")
    self._delrcpt = []	# record deleted rcpts for testing
    self._addrcpt = []	# record added rcpts for testing

  def log(self,*msg):
    for i in msg: print >>self.logfp, i,
    print >>self.logfp

  def getsymval(self,name):
    if name == 'j': return 'test.milter.org'
    return ''

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

  def connect(self,host='localhost'):
    self._body = None
    self.bodyreplaced = False
    rc =  bms.bmsMilter.connect(self,host,1,('1.2.3.4',1234)) 
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
    rc = milter.connect('testDefang')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg(fname)
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus1.out","r").read())
    fp.seek(0)
    msg = mime.message_from_file(fp)
    str = msg.get_payload(1).get_payload()
    milter.log(str)
    milter.close()

  # test some spams that crashed our parser
  def testParse(self,fname='spam7'):
    milter = TestMilter()
    milter.connect('testParse')
    rc = milter.feedMsg(fname)
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    milter.connect('pro-send.com')
    rc = milter.feedMsg('spam8')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg('bounce')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg('bounce1')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    milter.close()

  def testDefang2(self):
    milter = TestMilter()
    milter.connect('testDefang2')
    rc = milter.feedMsg('samp1')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg("virus3")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus3.tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus3.out","r").read())
    rc = milter.feedMsg("virus6")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    self.failUnless(milter.headerschanged,"Message headers not adjusted")
    fp = milter._body
    open("test/virus6.tstout","w").write(fp.getvalue())
    milter.close()

  def testDefang3(self):
    milter = TestMilter()
    milter.connect('testDefang3')
    # test script removal on complex HTML attachment
    rc = milter.feedMsg('amazon')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/amazon.tstout","w").write(fp.getvalue())
    # test defanging Klez virus
    rc = milter.feedMsg("virus13")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus13.tstout","w").write(fp.getvalue())
    # test script removal on quoted-printable HTML attachment
    # sgmllib can't handle the <![if cond]> syntax
    rc = milter.feedMsg('spam44')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter.bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/spam44.tstout","w").write(fp.getvalue())
    milter.close()
 
  def testRFC822(self):
    milter = TestMilter()
    milter.connect('testRFC822')
    # test encoded rfc822 attachment
    #pdb.set_trace()
    rc = milter.feedMsg('test8')
    self.assertEqual(rc,Milter.ACCEPT)
    # python2.4 doesn't scan encoded message attachments
    if sys.hexversion < 0x02040000:
      self.failUnless(milter.bodyreplaced,"Message body not replaced")
    #self.failIf(milter.bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/test8.tstout","w").write(fp.getvalue())
    rc = milter.feedMsg('virus7')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter.bodyreplaced,"Message body not replaced")
    #self.failIf(milter.bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/virus7.tstout","w").write(fp.getvalue())

  def testSmartAlias(self):
    milter = TestMilter()
    milter.connect('testSmartAlias')
    # test smart alias feature
    key = ('foo@example.com','baz@bat.com')
    bms.smart_alias[key] = ['ham@eggs.com']
    rc = milter.feedMsg('test8',key[0],key[1])
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._delrcpt == ['<baz@bat.com>'])
    self.failUnless(milter._addrcpt == ['<ham@eggs.com>'])
    # python2.4 email does not decode message attachments, so script
    # is not replaced
    if sys.hexversion < 0x02040000:
      self.failUnless(milter.bodyreplaced,"Message body not replaced")

  def testBadBoundary(self):
    milter = TestMilter()
    milter.connect('testBadBoundary')
    # test rfc822 attachment with invalid boundaries
    #pdb.set_trace()
    rc = milter.feedMsg('bound')
    if sys.hexversion < 0x02040000:
      # python2.4 adds invalid boundaries to decects list and makes
      # payload a str
      self.assertEqual(rc,Milter.REJECT)
      self.assertEqual(milter.reply[0],'554')
    #self.failUnless(milter.bodyreplaced,"Message body not replaced")
    self.failIf(milter.bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/bound.tstout","w").write(fp.getvalue())

  def testCompoundFilename(self):
    milter = TestMilter()
    milter.connect('testCompoundFilename')
    # test rfc822 attachment with invalid boundaries
    #pdb.set_trace()
    rc = milter.feedMsg('test1')
    self.assertEqual(rc,Milter.ACCEPT)
    #self.failUnless(milter.bodyreplaced,"Message body not replaced")
    self.failIf(milter.bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/test1.tstout","w").write(fp.getvalue())

  def testFindsrs(self):
    if not bms.srs:
      import SRS
      bms.srs = SRS.new(secret='test')
    sender = bms.srs.forward('foo@bar.com','mail.example.com')
    sndr = bms.findsrs(StringIO.StringIO(
"""Received: from [1.16.33.86] (helo=mail.example.com)
	by bastion4.mail.zen.co.uk with smtp (Exim 4.50) id 1H3IBC-00013b-O9
	for foo@bar.com; Sat, 06 Jan 2007 20:30:17 +0000
X-Mailer: "PyMilter-0.8.5"
	<%s> foo
MIME-Version: 1.0
Content-Type: text/plain
To: foo@bar.com
From: postmaster@mail.example.com
""" % sender
    ))
    self.assertEqual(sndr,'foo@bar.com')

#  def testReject(self):
#    "Test content based spam rejection."
#    milter = TestMilter()
#    milter.connect('gogo-china.com')
#    rc = milter.feedMsg('big5');
#    self.failUnless(rc == Milter.REJECT)
#    milter.close();

def suite(): 
  s = unittest.makeSuite(BMSMilterTestCase,'test')
  s.addTest(doctest.DocTestSuite(bms))
  return s

if __name__ == '__main__':
  if len(sys.argv) > 1:
    for fname in sys.argv[1:]:
      milter = TestMilter()
      milter.connect('main')
      fp = open(fname,'r')
      rc = milter.feedFile(fp)
      fp = milter._body
      sys.stdout.write(fp.getvalue())
  else:
    #unittest.main()
    unittest.TextTestRunner().run(suite())
