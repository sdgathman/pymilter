# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# A thin OO wrapper for the milter module

import os
import milter
import thread

from milter import ACCEPT,CONTINUE,REJECT,DISCARD,TEMPFAIL,	\
  set_flags, setdbg, setbacklog, settimeout, error,	\
  ADDHDRS, CHGBODY, ADDRCPT, DELRCPT, CHGHDRS,	\
  V1_ACTS, V2_ACTS, CURR_ACTS

try: from milter import QUARANTINE
except: pass

__version__ = '0.8.5'

_seq_lock = thread.allocate_lock()
_seq = 0

def uniqueID():
  """Return a sequence number unique to this process.
  """
  global _seq
  _seq_lock.acquire()
  seqno = _seq = _seq + 1
  _seq_lock.release()
  return seqno
  
class Milter:
  """A simple class interface to the milter module.
  """
  def _setctx(self,ctx):
    self.__ctx = ctx
    if ctx:
      ctx.setpriv(self)

  # user replaceable callbacks
  def log(self,*msg):
    print 'Milter:',
    for i in msg: print i,
    print

  def connect(self,hostname,family,hostaddr):
    "Called for each connection to sendmail."
    self.log("connect from %s at %s" % (hostname,hostaddr))
    return CONTINUE

  def hello(self,hostname):
    "Called after the HELO command."
    self.log("hello from %s" % hostname)
    return CONTINUE

  def envfrom(self,f,*str):
    """Called to begin each message.
    f -> string		message sender
    str -> tuple	additional ESMTP parameters
    """
    self.log("mail from",f,str)
    return CONTINUE

  def envrcpt(self,to,*str):
    "Called for each message recipient."
    self.log("rcpt to",to,str)
    return CONTINUE

  def header(self,field,value):
    "Called for each message header."
    self.log("%s: %s" % (field,value))
    return CONTINUE

  def eoh(self):
    "Called after all headers are processed."
    self.log("eoh")
    return CONTINUE

  def body(self,unused):
    "Called to transfer the message body."
    return CONTINUE

  def eom(self):
    "Called at the end of message."
    self.log("eom")
    return CONTINUE

  def abort(self):
    "Called if the connection is terminated abnormally."
    self.log("abort")
    return CONTINUE

  def close(self):
    "Called at the end of connection, even if aborted."
    self.log("close")
    return CONTINUE

  # Milter methods which can be invoked from callbacks
  def getsymval(self,sym):
    return self.__ctx.getsymval(sym)

  # If sendmail does not support setmlreply, then only the
  # first msg line is used.
  def setreply(self,rcode,xcode=None,msg=None,*ml):
    return self.__ctx.setreply(rcode,xcode,msg,*ml)

  # Milter methods which can only be called from eom callback.
  def addheader(self,field,value,idx=-1):
    return self.__ctx.addheader(field,value,idx)

  def chgheader(self,field,idx,value):
    return self.__ctx.chgheader(field,idx,value)

  def addrcpt(self,rcpt):
    return self.__ctx.addrcpt(rcpt)

  def delrcpt(self,rcpt):
    return self.__ctx.delrcpt(rcpt)

  def replacebody(self,body):
    return self.__ctx.replacebody(body)

  # When quarantined, a message goes into the mailq as if to be delivered,
  # but delivery is deferred until the message is unquarantined.
  def quarantine(self,reason):
    return self.__ctx.quarantine(reason)

  def progress(self):
    return self.__ctx.progress()

factory = Milter

def connectcallback(ctx,hostname,family,hostaddr):
  m = factory()
  m._setctx(ctx)
  return m.connect(hostname,family,hostaddr)

def closecallback(ctx):
  m = ctx.getpriv()
  if not m: return CONTINUE
  rc = m.close()
  m._setctx(None)	# release milterContext
  return rc

def dictfromlist(args):
  "Convert ESMTP parm list to keyword dictionary."
  kw = {}
  for s in args:
    pos = s.find('=')
    if pos > 0:
      kw[s[:pos].upper()] = s[pos+1:]
  return kw

def envcallback(c,args):
  """Call function c with ESMTP parms converted to keyword parameters.
  Can be used in the envfrom and/or envrcpt callbacks to process
  ESMTP parameters as python keyword parameters."""
  kw = {}
  pargs = [args[0]]
  for s in args[1:]:
    pos = s.find('=')
    if pos > 0:
      kw[s[:pos].upper()] = s[pos+1:]
    else:
      pargs.append(s)
  return c(*pargs,**kw)

def runmilter(name,socketname,timeout = 0):
  # This bit is here on the assumption that you will be starting this filter
  # before sendmail.  If sendmail is not running and the socket already exists,
  # libmilter will throw a warning.  If sendmail is running, this is still
  # safe if there are no messages currently being processed.  It's safer to
  # shutdown sendmail, kill the filter process, restart the filter, and then
  # restart sendmail.
  pos = socketname.find(':')
  if pos > 1:
    s = socketname[:pos]
    fname = socketname[pos+1:]
  else:
    s = "unix"
    fname = socketname
  if s == "unix" or s == "local":
    print "Removing %s" % fname
    try:
      os.unlink(fname)
    except os.error, x:
      import errno
      if x.errno != errno.ENOENT:
        raise milter.error(x)

  # The default flags set include everything
  # milter.set_flags(milter.ADDHDRS)
  milter.set_connect_callback(connectcallback)
  milter.set_helo_callback(lambda ctx, host: ctx.getpriv().hello(host))
  # For envfrom and envrcpt, we would like to convert ESMTP parms to keyword
  # parms, but then all existing users would have to include **kw to accept
  # arbitrary keywords without crashing.  We do provide envcallback and
  # dictfromlist to make parsing the ESMTP args convenient.
  milter.set_envfrom_callback(lambda ctx,*str: ctx.getpriv().envfrom(*str))
  milter.set_envrcpt_callback(lambda ctx,*str: ctx.getpriv().envrcpt(*str))
  milter.set_header_callback(lambda ctx,fld,val: ctx.getpriv().header(fld,val))
  milter.set_eoh_callback(lambda ctx: ctx.getpriv().eoh())
  milter.set_body_callback(lambda ctx,chunk: ctx.getpriv().body(chunk))
  milter.set_eom_callback(lambda ctx: ctx.getpriv().eom())
  milter.set_abort_callback(lambda ctx: ctx.getpriv().abort())
  milter.set_close_callback(closecallback)

  milter.setconn(socketname)
  if timeout > 0: milter.settimeout(timeout)
  # The name *must* match the X line in sendmail.cf (supposedly)
  milter.register(name)
  start_seq = _seq
  try:
    milter.main()
  except milter.error:
    if start_seq == _seq: raise	# couldn't start
    # milter has been running for a while, but now it can't start new threads
    raise milter.error("out of thread resources")

__all__ = globals().copy()
for priv in ('os','milter','thread','factory','_seq','_seq_lock','__version__'):
  del __all__[priv]
__all__ = __all__.keys()
