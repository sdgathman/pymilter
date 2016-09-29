# $Log$
# Revision 1.5  2011/06/09 17:27:42  customdesigned
# Documentation updates.
#
# Revision 1.4  2005/07/20 14:49:44  customdesigned
# Handle corrupt and empty ZIP files.
#
# Revision 1.3  2005/06/17 01:49:39  customdesigned
# Handle zip within zip.
#
# Revision 1.2  2005/06/02 15:00:17  customdesigned
# Configure banned extensions.  Scan zipfile option with test case.
#
# Revision 1.1.1.2  2005/05/31 18:23:49  customdesigned
# Development changes since 0.7.2
#
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
from __future__ import print_function
import unittest
import mime
import socket
try:
  from StringIO import StringIO
except:
  from io import StringIO
import email
import sys
import Milter
try:
  from email import Errors as errors
except:
  from email import errors

samp1_txt1 = """Dear Agent 1
I hope you can read this.  Whenever you write label it  P.B.S kids.
   Eliza doesn't know a thing about  P.B.S kids.   got to go by
agent one."""

hostname = socket.gethostname()

class MimeTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testParam(self):
    plist = mime._parseparam('; boundary="----=_NextPart_000_4e56_490d_48e3"')
    plist = [ x for x in plist if x ] # py2 doesn't include empty params
    self.assertEqual(1,len(plist))
    self.assertTrue(plist[0] == 'boundary="----=_NextPart_000_4e56_490d_48e3"')
    plist = mime._parseparam('; name="Jim&amp;amp;Girlz.jpg"')
    plist = [ x for x in plist if x ] # py2 doesn't include empty params
    self.assertEqual(1,len(plist))
    self.assertTrue(plist[0] == 'name="Jim&amp;amp;Girlz.jpg"')

  def testParse(self,fname='samp1'):
    with open('test/'+fname,"rb") as fp:
      msg = mime.message_from_file(fp)
    self.assertTrue(msg.ismultipart())
    parts = msg.get_payload()
    self.assertTrue(len(parts) == 2)
    txt1 = parts[0].get_payload()
    self.assertTrue(txt1.rstrip() == samp1_txt1,txt1)
    with open('test/missingboundary',"rb") as fp:
      msg = mime.message_from_file(fp)
    # should get no exception as long as we don't try to parse
    # message attachments
    mime.defang(msg,scan_rfc822=False)
    with open('test/missingboundary.out','wb') as fp:
      msg.dump(fp)
    with open('test/missingboundary',"rb") as fp:
      msg = mime.message_from_file(fp)
    try:
      mime.defang(msg)
      # python 2.4 doesn't get exceptions on missing boundaries, and
      # if message is modified, output is readable by mail clients
      if sys.hexversion < 0x02040000:
        self.fail('should get boundary error parsing bad rfc822 attachment')
    except errors.BoundaryError:
      pass
  
  def testDefang(self,vname='virus1',part=1,
	fname='LOVE-LETTER-FOR-YOU.TXT.vbs'):
    with open('test/'+vname,"rb") as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg,scan_zip=True)
    self.assertTrue(msg.ismodified(),"virus not removed")
    oname = vname + '.out'
    with open('test/'+oname,"wb") as fp:
      msg.dump(fp)
    with open('test/'+oname,"rb") as fp:
      msg = mime.message_from_file(fp)
    txt2 = msg.get_payload()
    if type(txt2) == list:
      txt2 = txt2[part].get_payload()
    self.assertTrue(
      txt2.rstrip()+'\n' == mime.virus_msg % (fname,hostname,None),txt2)

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
    with open('test/'+vname,"rb") as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg)
    oname = vname + '.out'
    with open('test/'+oname,"wb") as fp:
      msg.dump(fp)
    with open('test/'+oname,"rb") as fp:
      msg = mime.message_from_file(fp)
    self.assertFalse(msg.ismultipart())
    txt2 = msg.get_payload()
    self.assertTrue(txt2 == mime.virus_msg % \
	(fname,hostname,None),txt2)

  # honey virus has a sneaky ASP payload which is parsed correctly
  # by email package in python-2.2.2, but not by mime.MimeMessage or 2.2.1
  def testDefang7(self,vname="honey",fname='story[1].scr'):
    with open('test/'+vname,"rb") as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg)
    oname = vname + '.out'
    with open('test/'+oname,"wb") as fp:
      msg.dump(fp)
    with open('test/'+oname,"rb") as fp:
      msg = mime.message_from_file(fp)
    parts = msg.get_payload()
    txt2 = parts[1].get_payload()
    txt3 = parts[2].get_payload()
    self.assertTrue(txt2.rstrip()+'\n' == mime.virus_msg % \
	(fname,hostname,None),txt2)
    if txt3 != '':
      self.assertTrue(txt3.rstrip()+'\n' == mime.virus_msg % \
	  ('story[1].asp',hostname,None),txt3)

  def testParse2(self,fname="spam7"):
    with open('test/'+fname,"rb") as fp:
      msg = mime.message_from_file(fp)
    self.assertTrue(msg.ismultipart())
    parts = msg.get_payload()
    self.assertTrue(len(parts) == 2)
    name = parts[1].getname()
    self.assertTrue(name == "Jim&amp;amp;Girlz.jpg","name=%s"%name)

  def testZip(self,vname="zip1",fname='zip.zip'):
    self.testDefang(vname,1,'zip.zip')
    # test scan_zip flag
    with open('test/'+vname,"rb") as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg,scan_zip=False)
    self.assertFalse(msg.ismodified())
    # test ignoring empty zip (often found in DSNs)
    with open('test/zip2','rb') as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg,scan_zip=True)
    self.assertFalse(msg.ismodified())
    # test corrupt zip (often an EXE named as a ZIP)
    self.testDefang('zip3',1,'zip.zip')
    # test zip within zip
    self.testDefang('ziploop',1,'stuart@bmsi.com.zip')

  def _chk_name(self,name):
    self.filename = name

  def _chk_attach(self,msg):
    "Filter attachments by content."
    # check for bad extensions
    mime.check_name(msg,ckname=self._chk_name,scan_zip=True)
    # remove scripts from HTML
    mime.check_html(msg)
    # don't let a tricky virus slip one past us
    msg = msg.get_submsg()
    if isinstance(msg,email.message.Message):
      return mime.check_attachments(msg,self._chk_attach)
    return Milter.CONTINUE

  def testCheckAttach(self,fname="test1"):
    # test1 contains a very long filename
    with open('test/'+fname,'rb') as fp:
      msg = mime.message_from_file(fp)
    mime.defang(msg,scan_zip=True)
    self.assertFalse(msg.ismodified())
    with open('test/test2','rb') as fp:
      msg = mime.message_from_file(fp)
    rc = mime.check_attachments(msg,self._chk_attach)
    self.assertEqual(self.filename,"7501'S FOR TWO GOLDEN SOURCES SHIPMENTS FOR TAX & DUTY PURPOSES ONLY.PDF")
    self.assertEqual(rc,Milter.CONTINUE)

  def testHTML(self,fname=""):
    result = StringIO()
    filter = mime.HTMLScriptFilter(result)
    msg = """<! Illegal declaration used as comment>
      <![if conditional]> Optional SGML <![endif]>
      <!-- Legal SGML comment -->
    """
    script = "<script lang=javascript> Dangerous script </script>"
    filter.feed(msg + script)
    filter.close()
    #print(result.getvalue())
    #print('---')
    #print(msg + filter.msg)
    self.assertTrue(result.getvalue() == msg + filter.msg)

def suite(): return unittest.makeSuite(MimeTestCase,'test')

if __name__ == '__main__':
  if len(sys.argv) < 2:
    unittest.main()
  else:
    for fname in sys.argv[1:]:
      with open(fname,'rb') as fp:
        msg = mime.message_from_file(fp)
      mime.defang(msg,scan_zip=True)
      print(msg.as_string())
