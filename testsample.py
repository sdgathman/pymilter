import unittest
import Milter
import sample
import mime
from Milter.test import TestBase

class TestMilter(TestBase,sample.sampleMilter):
  def __init__(self):
    TestBase.__init__(self)
    sample.sampleMilter.__init__(self)

class BMSMilterTestCase(unittest.TestCase):

  def testDefang(self,fname='virus1'):
    milter = TestMilter()
    milter.setsymval('{auth_authen}','batman')
    milter.setsymval('{auth_type}','batcomputer')
    milter.setsymval('j','mailhost')
    rc = milter.connect()
    self.assertTrue(rc == Milter.CONTINUE)
    rc = milter.feedMsg(fname)
    self.assertTrue(milter.user == 'batman',"getsymval failed")
    self.assertTrue(milter.auth_type != 'batcomputer',"setsymlist failed")
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
    rc = milter.feedMsg("virus3")
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus3.tstout","wb").write(fp.getvalue())
    #self.assertTrue(fp.getvalue() == open("test/virus3.out","r").read())
    rc = milter.feedMsg("virus6")
    self.assertTrue(rc == Milter.ACCEPT)
    self.assertTrue(milter._bodyreplaced,"Message body not replaced")
    self.assertTrue(milter._headerschanged,"Message headers not adjusted")
    fp = milter._body
    open("test/virus6.tstout","wb").write(fp.getvalue())
    milter.close()

def suite(): return unittest.makeSuite(BMSMilterTestCase,'test')

if __name__ == '__main__':
  unittest.main()
