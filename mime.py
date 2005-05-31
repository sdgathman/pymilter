# $Log$
# Revision 1.54  2004/08/18 01:59:46  stuart
# Handle mislabeled multipart messages
#
# Revision 1.53  2004/04/24 22:53:20  stuart
# Rename some local variables to avoid shadowing builtins
#
# Revision 1.52  2004/04/24 22:47:13  stuart
# Convert header values to str
#
# Revision 1.51  2004/03/25 03:19:10  stuart
# Correctly defang rfc822 attachments when boundary specified with
# content-type message/rfc822.
#
# Revision 1.50  2003/10/15 22:01:00  stuart
# Test for and work around email bug with encoded filenames.
#
# Revision 1.49  2003/09/04 18:48:13  stuart
# Support python-2.2.3
#
# Revision 1.48  2003/09/02 00:27:27  stuart
# Should have full milter based dspam support working
#
# Revision 1.47  2003/08/26 06:08:18  stuart
# Use new python boolean since we now require 2.2.2
#
# Revision 1.46  2003/08/26 05:01:38  stuart
# Release 0.6.0
#
# Revision 1.45  2003/08/26 04:01:24  stuart
# Use new email module for parsing mail.  Still need mime module to
# provide various bug fixes to email module, and maintain some compatibility
# with old milter code.
#

# This module provides a "defang" function to replace naughty attachments
# with a warning message.

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import StringIO
import socket
import Milter
import email
import email.Message
from email.Message import Message
from email.Generator import Generator
from email.Utils import quote
from email import Utils

from types import ListType,StringType

# Enhance email.Parser
# - Fix _parsebody to decode message attachments before parsing

from email.Parser import Parser
try: from email.Parser import NLCRE
except: from email.Parser import nlcre as NLCRE

from email import Errors

class MimeGenerator(Generator):
    def _dispatch(self, msg):
        # Get the Content-Type: for the message, then try to dispatch to
        # self._handle_<maintype>_<subtype>().  If there's no handler for the
        # full MIME type, then dispatch to self._handle_<maintype>().  If
        # that's missing too, then dispatch to self._writeBody().
        main = msg.get_content_maintype()
	if msg.is_multipart() and main.lower() != 'multipart':
	  self._handle_multipart(msg)
	else:
	  Generator._dispatch(self,msg)

class MimeParser(Parser):

    # This is a copy of _parsebody from email.Parser, with a fix
    # for message attachments.  I couldn't find a smaller way to patch it
    # in a subclass.

    def _parsebody(self, container, fp, firstbodyline=None):
        # Parse the body, but first split the payload on the content-type
        # boundary if present.
        boundary = container.get_boundary()
        isdigest = (container.get_content_type() == 'multipart/digest')
        # If there's a boundary, split the payload text into its constituent
        # parts and parse each separately.  Otherwise, just parse the rest of
        # the body as a single message.  Note: any exceptions raised in the
        # recursive parse need to have their line numbers coerced.
        if boundary:
            preamble = epilogue = None
            # Split into subparts.  The first boundary we're looking for won't
            # always have a leading newline since we're at the start of the
            # body text, and there's not always a preamble before the first
            # boundary.
            separator = '--' + boundary
            payload = fp.read()
            if firstbodyline is not None:
                payload = firstbodyline + '\n' + payload
            # We use an RE here because boundaries can have trailing
            # whitespace.
            mo = re.search(
                r'(?P<sep>' + re.escape(separator) + r')(?P<ws>[ \t]*)',
                payload)
            if not mo:
                if self._strict:
                    raise Errors.BoundaryError(
                        "Couldn't find starting boundary: %s" % boundary)
                container.set_payload(payload)
                return
            start = mo.start()
            if start > 0:
                # there's some pre-MIME boundary preamble
                preamble = payload[0:start]
            # Find out what kind of line endings we're using
            start += len(mo.group('sep')) + len(mo.group('ws'))
            mo = NLCRE.search(payload, start)
            if mo:
                start += len(mo.group(0))
            # We create a compiled regexp first because we need to be able to
            # specify the start position, and the module function doesn't
            # support this signature. :(
            cre = re.compile('(?P<sep>\r\n|\r|\n)' +
                             re.escape(separator) + '--')
            mo = cre.search(payload, start)
            if mo:
                terminator = mo.start()
                linesep = mo.group('sep')
                if mo.end() < len(payload):
                    # There's some post-MIME boundary epilogue
                    epilogue = payload[mo.end():]
            elif self._strict:
                raise Errors.BoundaryError(
                        "Couldn't find terminating boundary: %s" % boundary)
            else:
                # Handle the case of no trailing boundary.  Check that it ends
                # in a blank line.  Some cases (spamspamspam) don't even have
                # that!
                mo = re.search('(?P<sep>\r\n|\r|\n){2}$', payload)
                if not mo:
                    mo = re.search('(?P<sep>\r\n|\r|\n)$', payload)
                    if not mo:
                        raise Errors.BoundaryError(
                          'No terminating boundary and no trailing empty line')
                linesep = mo.group('sep')
                terminator = len(payload)
            # We split the textual payload on the boundary separator, which
            # includes the trailing newline. If the container is a
            # multipart/digest then the subparts are by default message/rfc822
            # instead of text/plain.  In that case, they'll have a optional
            # block of MIME headers, then an empty line followed by the
            # message headers.
            parts = re.split(
                linesep + re.escape(separator) + r'[ \t]*' + linesep,
                payload[start:terminator])
            for part in parts:
                if isdigest:
                    if part.startswith(linesep):
                        # There's no header block so create an empty message
                        # object as the container, and lop off the newline so
                        # we can parse the sub-subobject
                        msgobj = self._class()
                        part = part[len(linesep):]
                    else:
                        parthdrs, part = part.split(linesep+linesep, 1)
                        # msgobj in this case is the "message/rfc822" container
                        msgobj = self.parsestr(parthdrs, headersonly=1)
                    # while submsgobj is the message itself
                    msgobj.set_default_type('message/rfc822')
                    maintype = msgobj.get_content_maintype()
                    if maintype in ('message', 'multipart'):
                        submsgobj = self.parsestr(part)
                        msgobj.attach(submsgobj)
                    else:
                        msgobj.set_payload(part)
                else:
                    msgobj = self.parsestr(part)
                container.preamble = preamble
                container.epilogue = epilogue
                container.attach(msgobj)
        elif container.get_main_type() == 'multipart':
            # Very bad.  A message is a multipart with no boundary!
            raise Errors.BoundaryError(
                'multipart message with no defined boundary')
        elif container.get_type() == 'message/delivery-status':
            # This special kind of type contains blocks of headers separated
            # by a blank line.  We'll represent each header block as a
            # separate Message object
            blocks = []
            while True:
                blockmsg = self._class()
                self._parseheaders(blockmsg, fp)
                if not len(blockmsg):
                    # No more header blocks left
                    break
                blocks.append(blockmsg)
            container.set_payload(blocks)
        elif container.get_main_type() == 'message':
            # Create a container for the payload, but watch out for there not
            # being any headers left
            container.set_payload(fp.read())
	    fp = StringIO.StringIO(container.get_payload(decode=True))
            try:
                msg = self.parse(fp)
            except Errors.HeaderParseError:
                msg = self._class()
                self._parsebody(msg, fp)
            container.set_payload([msg])
        else:
            text = fp.read()
            if firstbodyline is not None:
                text = firstbodyline + '\n' + text
            container.set_payload(text)

def unquote(s):
    """Remove quotes from a string."""
    if len(s) > 1:
        if s.startswith('"'):
	  if s.endswith('"'):
            s = s[1:-1]
	  else: # remove garbage after trailing quote
	    try: s = s[1:s[1:].index('"')+1]
	    except: return s
	  return s.replace('\\\\', '\\').replace('\\"', '"')
        if s.startswith('<') and s.endswith('>'):
            return s[1:-1]
    return s

from types import TupleType

def _unquotevalue(value):
  if isinstance(value, TupleType):
      return value[0], value[1], unquote(value[2])
  else:
      return unquote(value)

email.Message._unquotevalue = _unquotevalue

def _parseparam(s):
    plist = []
    while s[:1] == ';':
	s = s[1:]
	end = s.find(';')
	while end > 0 and (s.count('"',0,end) & 1):
	  end = s.find(';',end + 1)
	if end < 0: end = len(s)
	f = s[:end]
	if '=' in f:
	    i = f.index('=')
	    f = f[:i].strip().lower() + \
		    '=' + f[i+1:].strip()
	plist.append(f.strip())
	s = s[end:]
    return plist

# Enhance email.Message 
# - Fix getparam to parse attributes IE style
# - Provide a headerchange event for integration with Milter
#   Headerchange attribute can be assigned a function to be called when
#   changing headers.  The signature is:
#	headerchange(msg,name,value) -> None
# - Track modifications to headers of body or any part independently

class MimeMessage(Message):
  """Version of email.Message.Message compatible with old mime module
  """
  def __init__(self,fp=None,seekable=1):
    self.headerchange = None
    self.submsg = None
    Message.__init__(self)
    self.fp = fp
    if fp:
      parser = MimeParser(MimeMessage)
      self.startofheaders = fp.tell()
      parser._parseheaders(self,fp)
      self.startofbody = fp.tell()
      parser._parsebody(self,fp)
    for part in self.walk():
      part.modified = False

  def rewindbody(self):
    return self.fp.seek(self.startofbody)

  # override param parsing to handle quotes
  def _get_params_preserve(self,failobj=None,header='content-type'):
    "Return all parameter names and values. Use parser that handles quotes."
    missing = []
    value = self.get(header, missing)
    if value is missing:
	return failobj
    params = []
    for p in _parseparam(';' + value):
	  try:
	      name, val = p.split('=', 1)
	      name = name.strip()
	      val = val.strip()
	  except ValueError:
	      # Must have been a bare attribute
	      name = p.strip()
	      val = ''
	  params.append((name, val))
    params = Utils.decode_params(params)
    return params

  def get_filename(self, failobj=None):
      """Return the filename associated with the payload if present.

      The filename is extracted from the Content-Disposition header's
      `filename' parameter, and it is unquoted.
      """
      missing = []
      filename = self.get_param('filename', missing, 'content-disposition')
      if filename is missing:
	  return failobj
      if isinstance(filename, TupleType):
	  # It's an RFC 2231 encoded parameter
	  newvalue = _unquotevalue(filename)
	  if newvalue[0]:
	    return unicode(newvalue[2], newvalue[0])
	  return unicode(newvalue[2])
      else:
	  newvalue = _unquotevalue(filename.strip())
	  return newvalue

  getfilename = get_filename
  ismultipart = Message.is_multipart
  getheaders = Message.get_all
  gettype = Message.get_content_type
  getparam = Message.get_param

  def getparams(self): return self.get_params([])

  def getname(self):
    return self.get_param('name')

  def getnames(self):
    """Return a list of (attr,name) pairs of attributes that IE might
       interpret as a name - and hence decide to execute this message."""
    names = []
    for attr,val in self.get_params([]):
      if isinstance(val, TupleType):
	  # It's an RFC 2231 encoded parameter
	  newvalue = _unquotevalue(val)
	  if val[0]:
	    val =  unicode(newvalue[2], newvalue[0])
	  else:
	    val = unicode(newvalue[2])
      else:
	  val = _unquotevalue(val.strip())
      names.append((attr,val))
    return names + [("filename",self.get_filename())]

  def ismodified(self):
    "True if this message or a subpart has been modified."
    if not self.is_multipart():
      if self.submsg:
        return self.submsg.ismodified()
      return self.modified
    if self.modified: return True
    for i in self.get_payload():
      if i.ismodified(): return True
    return False

  def dump(self,file,unixfrom=False):
    "Write this message (and all subparts) to a file"
    g = MimeGenerator(file)
    g.flatten(self,unixfrom=unixfrom)

  def as_string(self, unixfrom=False):
      "Return the entire formatted message as a string."
      fp = StringIO.StringIO()
      self.dump(fp,unixfrom=unixfrom)
      return fp.getvalue()

  def getencoding(self):
    return self.get('content-transfer-encoding',None)

  # Decode body to stream according to transfer encoding, return encoding name
  def decode(self,filt):
    try:
      filt.write(self.get_payload(decode=True))
    except:
      pass
    return self.getencoding()

  def get_payload_decoded(self):
    return self.get_payload(decode=True)

  def __setitem__(self, name, value):
    rc = Message.__setitem__(self,name,value)
    self.modified = True
    if self.headerchange: self.headerchange(self,name,str(value))
    return rc

  def __delitem__(self, name):
    if self.headerchange: self.headerchange(self,name,None)
    rc = Message.__delitem__(self,name)
    self.modified = True
    return rc

  def get_payload(self,i=None,decode=False):
    msg = self.submsg
    if msg and msg.ismodified():
      self.set_payload([msg])
    return Message.get_payload(self,i,decode)

  def set_payload(self, val, charset=None):
    self.modified = True
    try:
      val.seek(0)
      val = val.read()
    except: pass
    Message.set_payload(self,val,charset)
    self.submsg = None

  def get_submsg(self):
    if self.get_content_type().lower() == 'message/rfc822':
      if not self.submsg:
        txt = self.get_payload()
	if type(txt) == str:
	  txt = self.get_payload(decode=True)
	  parser = MimeParser(MimeMessage)
	  self.submsg = parser.parsestr(txt)
	else:
	  self.submsg = txt[0]
      return self.submsg
    return None

extlist = ''.join("""
ade,adp,asd,asx,asp,bas,bat,chm,cmd,com,cpl,crt,dll,exe,hlp,hta,inf,ins,isp,js,
jse,lnk,mdb,mde,msc,msi,msp,mst,ocx,pcd,pif,reg,scr,sct,shs,url,vb,vbe,vbs,wsc,
wsf,wsh 
""".split())
bad_extensions = map(lambda x:'.' + x,extlist.split(','))

def check_ext(name):
  "Check a name for dangerous Winblows extensions."
  if not name: return name
  lname = name.lower()
  for ext in bad_extensions:
    if lname.endswith(ext): return name
  return None

virus_msg = """This message appeared to contain a virus.
It was originally named '%s', and has been removed.
A copy of your original message was saved as '%s:%s'.
See your administrator.
"""

def check_name(msg,savname=None,ckname=check_ext):
  "Replace attachment with a warning if its name is suspicious."
  for key,name in msg.getnames():
    badname = ckname(name)
    if badname:
      hostname = socket.gethostname()
      msg.set_payload(virus_msg % (badname,hostname,savname))
      del msg["content-type"]
      del msg["content-disposition"]
      del msg["content-transfer-encoding"]
      name = "WARNING.TXT"
      msg["Content-Type"] = "text/plain; name="+name
      break
  return Milter.CONTINUE

import email.Iterators

def check_attachments(msg,check):
  """Scan attachments.
msg	MimeMessage
check	function(MimeMessage): int
	Return CONTINUE, REJECT, ACCEPT
  """
  if msg.ismultipart() and not msg.get_content_type() == 'message/rfc822':
    for i in msg.get_payload():
      rc = check_attachments(i,check)
      if rc != Milter.CONTINUE: return rc
    return Milter.CONTINUE
  return check(msg)

# save call context for Python without nested_scopes
class _defang:
  def __init__(self,savname,check):
    self._savname = savname
    self._check = check
    self.scan_rfc822 = True
    self.scan_html = True
  def _chk_name(self,msg):
    rc = check_name(msg,self._savname,self._check)
    if self.scan_html:
      check_html(msg,self._savname)	# remove scripts from HTML
    if self.scan_rfc822:
      msg = msg.get_submsg()
      if msg: return check_attachments(msg,self._chk_name)
    return rc

# emulate old defang function
def defang(msg,savname=None,check=check_ext):
  """Compatible entry point.
Replace all attachments with dangerous names."""
  check_attachments(msg,_defang(savname,check)._chk_name)
  if msg.ismodified():
    return 1;
  return 0

import sgmllib

import re
declname = re.compile(r'[a-zA-Z][-_.a-zA-Z0-9]*\s*')
declstringlit = re.compile(r'(\'[^\']*\'|"[^"]*")\s*')

class SGMLFilter(sgmllib.SGMLParser):
  """Parse HTML and pass through all constructs unchanged.  It is intended for
     derived classes to implement exceptional processing for selected cases.
  """
  def __init__(self,out):
    sgmllib.SGMLParser.__init__(self)
    self.out = out

  def handle_comment(self,comment):
    self.out.write("<!--%s-->" % comment)

  def unknown_starttag(self,tag,attr):
    if hasattr(self,"get_starttag_text"):
      self.out.write(self.get_starttag_text())
    else:
      self.out.write("<%s" % tag)
      for (key,val) in attr:
        self.out.write(' %s="%s"' % (key,val))
      self.out.write('>')

  def handle_data(self,data):
    self.out.write(data)

  def handle_entityref(self,ref):
    self.out.write("&%s;" % ref)

  def handle_charref(self,ref):
    self.out.write("&#%s;" % ref)
      
  def unknown_endtag(self,tag):
    self.out.write("</%s>" % tag)

  def handle_special(self,data):
    self.out.write("<!%s>" % data)

  def write(self,buf):
    "Act like a writer.  Why doesn't SGMLParser do this by default?"
    self.feed(buf)

  # Python-2.1 sgmllib rejects illegal declarations.  Since various Microsoft
  # products accept and output them, we need to pass them through -
  # at least until we discover that MS will execute them.
  # sgmlop-1.1 will not use this method, but calls handle_special to
  # do what we want.
  def parse_declaration(self, i):
      rawdata = self.rawdata
      n = len(rawdata)
      j = i + 2
      while j < n:
	  c = rawdata[j]
	  if c == ">":
	      # end of declaration syntax
	      self.handle_special(rawdata[i+2:j])
	      return j + 1
	  if c in "\"'":
	      m = declstringlit.match(rawdata, j)
	      if not m:
		  # incomplete or an error?
		  return -1
	      j = m.end()
	  elif c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
	      m = declname.match(rawdata, j)
	      if not m:
		  # incomplete or an error?
		  return -1
	      j = m.end()
	  else:
	      j += 1
      # end of buffer between tokens
      return -1

class HTMLScriptFilter(SGMLFilter):
  "Remove scripts from an HTML document."
  def __init__(self,out):
    SGMLFilter.__init__(self,out)
    self.ignoring = 0
    self.modified = False
    self.msg = "<!-- WARNING: embedded script removed -->"
  def start_script(self,unused):
    self.ignoring += 1
    self.modified = True
    self.out.write(self.msg)
  def end_script(self):
    self.ignoring -= 1
  def handle_data(self,data):
    if not self.ignoring: SGMLFilter.handle_data(self,data)
  def handle_comment(self,comment):
    if not self.ignoring: SGMLFilter.handle_comment(self,comment)

def check_html(msg,savname=None):
  "Remove scripts from HTML attachments."
  msgtype = msg.get_content_type().lower()
  # check for more MSIE braindamage
  if msgtype == 'application/octet-stream':
    for (attr,name) in msg.getnames():
      if name and name.lower().endswith(".htm"):
	msgtype = 'text/html'
  if msgtype == 'text/html':
    out = StringIO.StringIO()
    htmlfilter = HTMLScriptFilter(out)
    try:
      htmlfilter.write(msg.get_payload(decode=True))
      htmlfilter.close()
    #except sgmllib.SGMLParseError:
    except:
      #mimetools.copyliteral(msg.get_payload(),open('debug.out','w')
      htmlfilter.close()
      hostname = socket.gethostname()
      msg.set_payload(
  "An HTML attachment could not be parsed.  The original is saved as '%s:%s'"
      % (hostname,savname))
      del msg["content-type"]
      del msg["content-disposition"]
      del msg["content-transfer-encoding"]
      name = "WARNING.TXT"
      msg["Content-Type"] = "text/plain; name="+name
      return Milter.CONTINUE
    if htmlfilter.modified:
      msg.set_payload(out)	# remove embedded scripts
      del msg["content-transfer-encoding"]
      email.Encoders.encode_quopri(msg)
  return Milter.CONTINUE
