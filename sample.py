
# A simple milter.

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import os
import StringIO
import rfc822
import mime
import Milter
import tempfile
from time import strftime
#import syslog

#syslog.openlog('milter')

class sampleMilter(Milter.Milter):
  "Milter to replace attachments poisonous to Windows with a WARNING message."

  def log(self,*msg):
    print "%s [%d]" % (strftime('%Y%b%d %H:%M:%S'),self.id),
    for i in msg: print i,
    print

  def __init__(self):
    self.tempname = None
    self.mailfrom = None
    self.fp = None
    self.bodysize = 0
    self.id = Milter.uniqueID()

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  def envfrom(self,f,*str):
    self.log("mail from",f,str)
    self.fp = StringIO.StringIO()
    self.tempname = None
    self.mailfrom = f
    self.bodysize = 0
    return Milter.CONTINUE

  def envrcpt(self,to,*str):
    # mail to MAILER-DAEMON is generally spam that bounced
    if to.startswith('<MAILER-DAEMON@'):
      self.log('DISCARD: RCPT TO:',to,str)
      return Milter.DISCARD
    self.log("rcpt to",to,str)
    return Milter.CONTINUE

  def header(self,name,val):
    lname = name.lower()
    if lname == 'subject':

      # even if we wanted the Taiwanese spam, we can't read Chinese
      # (delete if you read chinese mail)
      if val.startswith('=?big5') or val.startswith('=?ISO-2022-JP'):
	self.log('REJECT: %s: %s' % (name,val))
	#self.setreply('550','','Go away spammer')
	return Milter.REJECT

      # check for common spam keywords
      if val.find("$$$") >= 0 or val.find("XXX") >= 0	\
      	or val.find("!!!") >= 0 or val.find("FREE") >= 0:
	self.log('REJECT: %s: %s' % (name,val))
	#self.setreply('550','','Go away spammer')
	return Milter.REJECT

      # check for spam that pretends to be legal
      lval = val.lower()
      if lval.startswith("adv:") or lval.startswith("adv.") \
      	or lval.find('viagra') >= 0:
	self.log('REJECT: %s: %s' % (name,val))
	return Milter.REJECT

    # check for invalid message id
    if lname == 'message-id' and len(val) < 4:
      self.log('REJECT: %s: %s' % (name,val))
      #self.setreply('550','','Go away spammer')
      return Milter.REJECT

    # check for common bulk mailers
    if lname == 'x-mailer' and \
    	val.lower() in ('direct email','calypso','mail bomber'):
      self.log('REJECT: %s: %s' % (name,val))
      #self.setreply('550','','Go away spammer')
      return Milter.REJECT

    # log selected headers
    if lname in ('subject','x-mailer'):
      self.log('%s: %s' % (name,val))
    if self.fp:
      self.fp.write("%s: %s\n" % (name,val))	# add header to buffer
    return Milter.CONTINUE

  def eoh(self):
    if not self.fp: return Milter.TEMPFAIL	# not seen by envfrom
    self.fp.write("\n")
    self.fp.seek(0)
    # copy headers to a temp file for scanning the body
    headers = self.fp.getvalue()
    self.fp.close()
    self.tempname = fname = tempfile.mktemp(".defang")
    self.fp = open(fname,"w+b")
    self.fp.write(headers)	# IOError (e.g. disk full) causes TEMPFAIL
    return Milter.CONTINUE

  def body(self,chunk):		# copy body to temp file
    if self.fp:
      self.fp.write(chunk)	# IOError causes TEMPFAIL in milter
      self.bodysize += len(chunk)
    return Milter.CONTINUE

  def _headerChange(self,msg,name,value):
    if value:	# add header
      self.addheader(name,value)
    else:	# delete all headers with name
      h = msg.getheaders(name)
      cnt = len(h)
      for i in range(cnt,0,-1):
	self.chgheader(name,i-1,'')

  def eom(self):
    if not self.fp: return Milter.ACCEPT
    self.fp.seek(0)
    msg = mime.message_from_file(self.fp)
    msg.headerchange = self._headerChange
    if not mime.defang(msg,self.tempname):
      os.remove(self.tempname)
      self.tempname = None	# prevent re-removal
      self.log("eom")
      return Milter.ACCEPT	# no suspicious attachments
    self.log("Temp file:",self.tempname)
    self.tempname = None	# prevent removal of original message copy
    # copy defanged message to a temp file 
    out = tempfile.TemporaryFile()
    try:
      msg.dump(out)
      out.seek(0)
      msg = rfc822.Message(out)
      msg.rewindbody()
      while 1:
	buf = out.read(8192)
	if len(buf) == 0: break
	self.replacebody(buf)	# feed modified message to sendmail
      return Milter.ACCEPT	# ACCEPT modified message
    finally:
      out.close()
    return Milter.TEMPFAIL

  def close(self):
    sys.stdout.flush()		# make log messages visible
    if self.tempname:
      os.remove(self.tempname)	# remove in case session aborted
    if self.fp:
      self.fp.close()
    return Milter.CONTINUE

  def abort(self):
    self.log("abort after %d body chars" % self.bodysize)
    return Milter.CONTINUE

if __name__ == "__main__":
  #tempfile.tempdir = "/var/log/milter"
  #socketname = "/var/log/milter/pythonsock"
  socketname = os.getenv("HOME") + "/pythonsock"
  Milter.factory = sampleMilter
  Milter.set_flags(Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS)
  print """To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=pythonfilter
Xpythonfilter,        S=local:%s

See the sendmail README for libmilter.
sample  milter startup""" % socketname
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,240)
  print "sample milter shutdown"
