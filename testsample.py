import unittest
import Milter
import sample
import template
import mime
import zipfile
from Milter.test import TestBase
from Milter.testctx import TestCtx

class TestMilter(TestBase,sample.sampleMilter):
  def __init__(self):
    TestBase.__init__(self)
    sample.sampleMilter.__init__(self)

class BMSMilterTestCase(unittest.TestCase):

  def setUp(self):
    self.zf = zipfile.ZipFile('test/virus.zip','r')
    self.zf.setpassword(b'denatured')

  def tearDown(self):
    self.zf.close()
    self.zf = None

  def testTemplate(self,fname='test2'):
    ctx = TestCtx()
    Milter.factory = template.myMilter
    ctx._setsymval('{auth_authen}','batman')
    ctx._setsymval('{auth_type}','batcomputer')
    ctx._setsymval('j','mailhost')
    count = 10
    while count > 0:
      rc = ctx._connect(helo='milter-template.example.org')
      self.assertEquals(rc,Milter.CONTINUE)
      with open('test/'+fname,'rb') as fp:
        rc = ctx._feedFile(fp)
      milter = ctx.getpriv()
      self.assertFalse(ctx._bodyreplaced,"Message body replaced")
      ctx._close()
      count -= 1

  def testHeader(self,fname='utf8'):
    ctx = TestCtx()
    Milter.factory = sample.sampleMilter
    ctx._setsymval('{auth_authen}','batman')
    ctx._setsymval('{auth_type}','batcomputer')
    ctx._setsymval('j','mailhost')
    rc = ctx._connect()
    self.assertEquals(rc,Milter.CONTINUE)
    with open('test/'+fname,'rb') as fp:
      rc = ctx._feedFile(fp)
    milter = ctx.getpriv()
    self.assertFalse(ctx._bodyreplaced,"Message body replaced")
    fp = ctx._body
    with open('test/'+fname+".tstout","wb") as ofp:
      ofp.write(fp.getvalue())
    ctx._close()

  def testCtx(self,fname='virus1'):
    ctx = TestCtx()
    Milter.factory = sample.sampleMilter
    ctx._setsymval('{auth_authen}','batman')
    ctx._setsymval('{auth_type}','batcomputer')
    ctx._setsymval('j','mailhost')
    rc = ctx._connect()
    self.assertTrue(rc == Milter.CONTINUE)
    with self.zf.open(fname) as fp:
      rc = ctx._feedFile(fp)
    milter = ctx.getpriv()
#    self.assertTrue(milter.user == 'batman',"getsymval failed: "+
#        "%s != %s"%(milter.user,'batman'))
    self.assertEquals(milter.user,'batman')
    self.assertTrue(milter.auth_type != 'batcomputer',"setsymlist failed")
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(ctx._bodyreplaced,"Message body not replaced")
    fp = ctx._body
    open('test/'+fname+".tstout","wb").write(fp.getvalue())
    #self.assertTrue(fp.getvalue() == open("test/virus1.out","r").read())
    fp.seek(0)
    msg = mime.message_from_file(fp)
    s = msg.get_payload(1).get_payload()
    milter.log(s)
    ctx._close()

  def testDefang(self,fname='virus1'):
    milter = TestMilter()
    milter.setsymval('{auth_authen}','batman')
    milter.setsymval('{auth_type}','batcomputer')
    milter.setsymval('j','mailhost')
    rc = milter.connect()
    self.assertTrue(rc == Milter.CONTINUE)
    with self.zf.open(fname) as fp:
      rc = milter.feedFile(fp)
    self.assertTrue(milter.user == 'batman',"getsymval failed")
    # setsymlist not working in TestBase
    #self.assertTrue(milter.auth_type != 'batcomputer',"setsymlist failed")
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open('test/'+fname+".tstout","wb").write(fp.getvalue())
    #self.assertTrue(fp.getvalue() == open("test/virus1.out","r").read())
    fp.seek(0)
    msg = mime.message_from_file(fp)
    s = msg.get_payload(1).get_payload()
    milter.log(s)
    milter.close()

  def testParse(self,fname='spam7'):
    milter = TestMilter()
    milter.connect('somehost')
    rc = milter.feedMsg(fname)
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertFalse(milter._bodyreplaced,"Milter needlessly replaced body.")
    fp = milter._body
    open('test/'+fname+".tstout","wb").write(fp.getvalue())
    milter.close()

  def testDefang2(self):
    milter = TestMilter()
    milter.connect('somehost')
    rc = milter.feedMsg('samp1')
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertFalse(milter._bodyreplaced,"Milter needlessly replaced body.")
    with self.zf.open("virus3") as fp:
      rc = milter.feedFile(fp)
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus3.tstout","wb").write(fp.getvalue())
    #self.assertTrue(fp.getvalue() == open("test/virus3.out","r").read())
    with self.zf.open("virus6") as fp:
      rc = milter.feedFile(fp)
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(milter._bodyreplaced,"Message body not replaced")
    self.assertTrue(milter._headerschanged,"Message headers not adjusted")
    fp = milter._body
    open("test/virus6.tstout","wb").write(fp.getvalue())
    milter.close()

def suite(): return unittest.makeSuite(BMSMilterTestCase,'test')

if __name__ == '__main__':
  unittest.main()
