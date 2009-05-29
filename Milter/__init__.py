# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# A thin OO wrapper for the milter module

import os
import milter
import thread

from milter import *

__version__ = '0.9.2'

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

def nocallback(func):
  func.milter_protocol = 'NO'
  return func
def noreply(func):
  func.milter_protocol = 'NR'
  return func

class DisabledAction(RuntimeError):
  pass

# A do nothing Milter base class from which python milters should derive
# unless they are using the milter C module directly.

class Base(object):
  "The core class interface to the milter module."

  def __init__(self):
    self.__actions = CURR_ACTS         # all actions enabled
  def _setctx(self,ctx):
    self.__ctx = ctx
    if ctx:
      ctx.setpriv(self)
  @nocallback
  def connect(self,hostname,family,hostaddr): return CONTINUE
  @nocallback
  def hello(self,hostname): return CONTINUE
  @nocallback
  def envfrom(self,f,*str): return CONTINUE
  @nocallback
  def envrcpt(self,to,*str): return CONTINUE
  @nocallback
  def data(self): return CONTINUE
  @nocallback
  def header(self,field,value): return CONTINUE
  @nocallback
  def eoh(self): return CONTINUE
  @nocallback
  def body(self,unused): return CONTINUE
  @nocallback
  def eom(self): return CONTINUE
  @nocallback
  def abort(self): return CONTINUE
  @nocallback
  def unknown(self,cmd): return CONTINUE
  @nocallback
  def close(self): return CONTINUE
  def negotiate(self,opts):
    try:
      self.__actions,p,f1,f2 = opts
      for func,nr,nc in (
        (self.connect,P_NR_CONN,P_NOCONNECT),
        (self.hello,P_NR_HELO,P_NOHELO),
        (self.envfrom,P_NR_MAIL,P_NOMAIL),
        (self.envrcpt,P_NR_RCPT,P_NORCPT),
        (self.data,P_NR_DATA,P_NODATA),
        (self.unknown,P_NR_UNKN,P_NOUNKNOWN),
        (self.eoh,P_NR_EOH,P_NOEOH),
        (self.body,P_NR_BODY,P_NOBODY),
        (self.header,P_NR_HDR,P_NOHDRS)
      ):
        ca = getattr(func,'milter_protocol',None)
        if ca != 'NR': p &= ~nr
        elif p & nr: print func.__name__,'NOREPLY'
        if ca != 'NO': p &= ~nc
        elif p & nc: print func.__name__,'NOCALLBACK'
      p[1] = p & ~P_RCPT_REJ & ~P_HDR_LEADSPC
    except:
      # don't change anything if something went wrong
      return ALL_OPTS 
    return CONTINUE

  # Milter methods which can be invoked from most callbacks
  def getsymval(self,sym):
    return self.__ctx.getsymval(sym)

  # If sendmail does not support setmlreply, then only the
  # first msg line is used.
  def setreply(self,rcode,xcode=None,msg=None,*ml):
    return self.__ctx.setreply(rcode,xcode,msg,*ml)

  # may only be called from negotiate callback
  def setsmlist(self,stage,macros):
    if not self.__actions & SETSMLIST: raise DisabledAction("SETSMLIST")
    if type(macros) in (list,tuple):
      macros = ' '.join(macros)
    return self.__ctx.setsmlist(stage,macros)

  # Milter methods which can only be called from eom callback.
  def addheader(self,field,value,idx=-1):
    if not self.__actions & ADDHDRS: raise DisabledAction("ADDHDRS")
    return self.__ctx.addheader(field,value,idx)

  def chgheader(self,field,idx,value):
    if not self.__actions & CHGHDRS: raise DisabledAction("CHGHDRS")
    return self.__ctx.chgheader(field,idx,value)

  def addrcpt(self,rcpt,params=None):
    if not self.__actions & ADDRCPT: raise DisabledAction("ADDRCPT")
    return self.__ctx.addrcpt(rcpt,params)

  def delrcpt(self,rcpt):
    if not self.__actions & DELRCPT: raise DisabledAction("DELRCPT")
    return self.__ctx.delrcpt(rcpt)

  def replacebody(self,body):
    if not self.__actions & MODBODY: raise DisabledAction("MODBODY")
    return self.__ctx.replacebody(body)

  def chgfrom(self,sender,params=None):
    if not self.__actions & CHGFROM: raise DisabledAction("CHGFROM")
    return self.__ctx.chgfrom(sender,params)

  # When quarantined, a message goes into the mailq as if to be delivered,
  # but delivery is deferred until the message is unquarantined.
  def quarantine(self,reason):
    if not self.__actions & QUARANTINE: raise DisabledAction("QUARANTINE")
    return self.__ctx.quarantine(reason)

  def progress(self):
    return self.__ctx.progress()
  
# A logging but otherwise do nothing Milter base class included
# for compatibility with previous versions of pymilter.

class Milter(Base):
  "A simple class interface to the milter module."

  def log(self,*msg):
    print 'Milter:',
    for i in msg: print i,
    print

  @noreply
  def connect(self,hostname,family,hostaddr):
    "Called for each connection to sendmail."
    self.log("connect from %s at %s" % (hostname,hostaddr))
    return CONTINUE

  @noreply
  def hello(self,hostname):
    "Called after the HELO command."
    self.log("hello from %s" % hostname)
    return CONTINUE

  @noreply
  def envfrom(self,f,*str):
    """Called to begin each message.
    f -> string		message sender
    str -> tuple	additional ESMTP parameters
    """
    self.log("mail from",f,str)
    return CONTINUE

  @noreply
  def envrcpt(self,to,*str):
    "Called for each message recipient."
    self.log("rcpt to",to,str)
    return CONTINUE

  @noreply
  def header(self,field,value):
    "Called for each message header."
    self.log("%s: %s" % (field,value))
    return CONTINUE

  @noreply
  def eoh(self):
    "Called after all headers are processed."
    self.log("eoh")
    return CONTINUE

  @noreply
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

factory = Milter

def getpriv(ctx):
  m = ctx.getpriv()
  if not m:     # if not already created 
    m = factory()
    m._setctx(ctx)
  return m

def connectcallback(ctx,hostname,family,hostaddr):
  return getpriv(ctx).connect(hostname,family,hostaddr)

def closecallback(ctx):
  m = ctx.getpriv()
  if not m: return CONTINUE
  try:
    rc = m.close()
  finally:
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
  milter.set_connect_callback(lambda ctx,h,f,i: getpriv(ctx).connect(h,f,i))
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
  milter.register(name,
        data=lambda ctx: ctx.getpriv().data(),
        unknown=lambda ctx,cmd: ctx.getpriv().unknown(cmd),
        negotiate=lambda ctx,opt: getpriv(ctx).negotiate(opt)
  )
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
