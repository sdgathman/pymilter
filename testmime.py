# $Log$
# Revision 1.23  2005/02/11 18:34:14  stuart
# Handle garbage after quote in boundary.
#
# Revision 1.22  2005/02/10 01:10:59  stuart
# Fixed MimeMessage.ismodified()
#
# Revision 1.21  2005/02/10 00:56:49  stuart
# Runs with python2.4.  Defang not working correctly - more work needed.
#
# Revision 1.20  2004/11/20 16:38:17  stuart
# Add rcs log
#
import unittest
import mime
import socket
import StringIO
import email
import sys
from email import Errors

samp1_txt1 = """Dear Agent 1
I hope you can read this.  Whenever you write label it  P.B.S kids.
   Eliza doesn't know a thing about  P.B.S kids.   got to go by
agent one."""

hostname = socket.gethostname()

class MimeTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testParam(self):
    plist = mime._parseparam(
      '; boundary="----=_NextPart_000_4e56_490d_48e3"')
    self.failUnless(len(plist)==1)
    self.failUnless(plist[0] == 'boundary="----=_NextPart_000_4e56_490d_48e3"')
    plist = mime._parseparam('; name="Jim&amp;amp;Girlz.jpg"')
    self.failUnless(len(plist)==1)
    self.failUnless(plist[0] == 'name="Jim&amp;amp;Girlz.jpg"')

  def testParse(self,fname='samp1'):
    msg = mime.message_from_file(open('test/'+fname,"r"))
    self.failUnless(msg.ismultipart())
    parts = msg.get_payload()
    self.failUnless(len(parts) == 2)
    txt1 = parts[0].get_payload()
    self.failUnless(txt1.rstrip() == samp1_txt1,txt1)
    msg = mime.message_from_file(open('test/missingboundary',"r"))
    # should get no exception as long as we don't try to parse
    # message attachments
    mime.defang(msg,scan_rfc822=False)
    msg.dump(open('test/missingboundary.out','w'))
    msg = mime.message_from_file(open('test/missingboundary',"r"))
    try:
      mime.defang(msg)
      # python 2.4 doesn't get exceptions on missing boundaries, and
      # if message is modified, output is readable by mail clients
      if sys.hexversion < 0x02040000:
	self.fail('should get boundary error parsing bad rfc822 attachment')
    except Errors.BoundaryError:
      pass
  
  def testDefang(self,vname='virus1',part=1,
  	fname='LOVE-LETTER-FOR-YOU.TXT.vbs'):
    msg = mime.message_from_file(open('test/'+vname,"r"))
    mime.defang(msg)
    self.failUnless(msg.ismodified(),"virus not removed")
    oname = vname + '.out'
    msg.dump(open('test/'+oname,"w"))
    msg = mime.message_from_file(open('test/'+oname,"r"))
    txt2 = msg.get_payload()
    if type(txt2) == list:
      txt2 = txt2[part].get_payload()
    self.failUnless(txt2.rstrip()+'\n' == mime.virus_msg % (fname,hostname,None),txt2)

  def testDefang3(self):
    self.testDefang('virus3',0,'READER_DIGEST_LETTER.TXT.pif')

  # virus4 does not include proper end boundary
  def testDefang4(self):
    self.testDefang('virus4',1,'readme.exe')

  # virus5 is even more screwed up
  def testDefang5(self):
    self.testDefang('virus5',1,'whatever.exe')

  # virus6 has no parts - the virus is directly inline
  def testDefang6(self,vname="virus6",fname='FAX20.exe'):
    msg = mime.message_from_file(open('test/'+vname,"r"))
    mime.defang(msg)
    oname = vname + '.out'
    msg.dump(open('test/'+oname,"w"))
    msg = mime.message_from_file(open('test/'+oname,"r"))
    self.failIf(msg.ismultipart())
    txt2 = msg.get_payload()
    self.failUnless(txt2 == mime.virus_msg % \
    	(fname,hostname,None),txt2)

  # honey virus has a sneaky ASP payload which is parsed correctly
  # by email package in python-2.2.2, but not by mime.MimeMessage or 2.2.1
  def testDefang7(self,vname="honey",fname='story[1].scr'):
    msg = mime.message_from_file(open('test/'+vname,"r"))
    mime.defang(msg)
    oname = vname + '.out'
    msg.dump(open('test/'+oname,"w"))
    msg = mime.message_from_file(open('test/'+oname,"r"))
    parts = msg.get_payload()
    txt2 = parts[1].get_payload()
    txt3 = parts[2].get_payload()
    self.failUnless(txt2.rstrip()+'\n' == mime.virus_msg % \
    	(fname,hostname,None),txt2)
    if txt3 != '':
      self.failUnless(txt3.rstrip()+'\n' == mime.virus_msg % \
	  ('story[1].asp',hostname,None),txt3)

  def testParse2(self,fname="spam7"):
    msg = mime.message_from_file(open('test/'+fname,"r"))
    self.failUnless(msg.ismultipart())
    parts = msg.get_payload()
    self.failUnless(len(parts) == 2)
    name = parts[1].getname()
    self.failUnless(name == "Jim&amp;amp;Girlz.jpg","name=%s"%name)

  def testHTML(self,fname=""):
    result = StringIO.StringIO()
    filter = mime.HTMLScriptFilter(result)
    msg = """<! Illegal declaration used as comment>
      <![if conditional]> Optional SGML <![endif]>
      <!-- Legal SGML comment -->
    """
    script = "<script lang=javascript> Dangerous script </script>"
    filter.feed(msg + script)
    filter.close()
    #print result.getvalue()
    self.failUnless(result.getvalue() == msg + filter.msg)

def suite(): return unittest.makeSuite(MimeTestCase,'test')

if __name__ == '__main__':
  if len(sys.argv) < 2:
    unittest.main()
  else:
    for fname in sys.argv[1:]:
      fp = open(fname,'r')
      msg = mime.message_from_file(fp)
