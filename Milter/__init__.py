# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# A thin OO wrapper for the milter module

__version__ = '0.9.2'

import os
import milter
import thread

from milter import *

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

OPTIONAL_CALLBACKS = {
  'connect':(P_NR_CONN,P_NOCONNECT),
  'hello':(P_NR_HELO,P_NOHELO),
  'envfrom':(P_NR_MAIL,P_NOMAIL),
  'envrcpt':(P_NR_RCPT,P_NORCPT),
  'data':(P_NR_DATA,P_NODATA),
  'unknown':(P_NR_UNKN,P_NOUNKNOWN),
  'eoh':(P_NR_EOH,P_NOEOH),
  'body':(P_NR_BODY,P_NOBODY),
  'header':(P_NR_HDR,P_NOHDRS)
}

def nocallback(func):
  try:
    func.milter_protocol = OPTIONAL_CALLBACKS[func.__name__][1]
  except KeyError:
    raise ValueError(
      '@nocallback applied to non-optional method: '+func.__name__)
  return func

def noreply(func):
  try:
    nr_mask = OPTIONAL_CALLBACKS[func.__name__][0]
  except KeyErro:
    raise ValueError(
      '@noreply applied to non-optional method: '+func.__name__)
  def wrapper(self,*args):
    rc = func(self,*args)
    if self._protocol & nr_mask: return NOREPLY
    return rc
  wrapper.milter_protocol = nr_mask
  return wrapper

class DisabledAction(RuntimeError):
  pass

# A do nothing Milter base class from which python milters should derive
# unless they are using the milter C module directly.

class Base(object):
  "The core class interface to the milter module."

  def _setctx(self,ctx):
    self._ctx = ctx
    self._actions = CURR_ACTS         # all actions enabled by default
    self._protocol = 0                # no protocol options by default
    if ctx:
      ctx.setpriv(self)
  def log(self,*msg): pass
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
  def unknown(self,cmd): return CONTINUE
  def eom(self): return CONTINUE
  def abort(self): return CONTINUE
  def close(self): return CONTINUE

  # Return mask of SMFIP_N.. protocol option bits to clear for this class
  @classmethod
  def protocol_mask(klass):
    try:
      return klass._protocol_mask
    except AttributeError:
      p = 0
      for func,(nr,nc) in OPTIONAL_CALLBACKS.items():
        func = getattr(klass,func)
        ca = getattr(func,'milter_protocol',0)
        #print func,hex(nr),hex(nc),hex(ca)
        p |= (nr|nc) & ~ca
      klass._protocol_mask = p
      return p
    
  # Default negotiation sets P_NO* and P_NR* for callbacks
  # marked @nocallback and @noreply respectively
  def negotiate(self,opts):
    try:
      self._actions,p,f1,f2 = opts
      opts[1] = self._protocol = \
              p & ~self.protocol_mask() & ~P_RCPT_REJ & ~P_HDR_LEADSPC
      opts[2] = 0
      opts[3] = 0
      #self.log("Negotiated:",opts)
    except:
      # don't change anything if something went wrong
      return ALL_OPTS 
    return CONTINUE

  # Milter methods which can be invoked from most callbacks
  def getsymval(self,sym):
    return self._ctx.getsymval(sym)

  # If sendmail does not support setmlreply, then only the
  # first msg line is used.
  def setreply(self,rcode,xcode=None,msg=None,*ml):
    return self._ctx.setreply(rcode,xcode,msg,*ml)

  # may only be called from negotiate callback
  def setsmlist(self,stage,macros):
    if not self._actions & SETSMLIST: raise DisabledAction("SETSMLIST")
    if type(macros) in (list,tuple):
      macros = ' '.join(macros)
    return self._ctx.setsmlist(stage,macros)

  # Milter methods which can only be called from eom callback.
  def addheader(self,field,value,idx=-1):
    if not self._actions & ADDHDRS: raise DisabledAction("ADDHDRS")
    return self._ctx.addheader(field,value,idx)

  def chgheader(self,field,idx,value):
    if not self._actions & CHGHDRS: raise DisabledAction("CHGHDRS")
    return self._ctx.chgheader(field,idx,value)

  def addrcpt(self,rcpt,params=None):
    if not self._actions & ADDRCPT: raise DisabledAction("ADDRCPT")
    return self._ctx.addrcpt(rcpt,params)

  def delrcpt(self,rcpt):
    if not self._actions & DELRCPT: raise DisabledAction("DELRCPT")
    return self._ctx.delrcpt(rcpt)

  def replacebody(self,body):
    if not self._actions & MODBODY: raise DisabledAction("MODBODY")
    return self._ctx.replacebody(body)

  def chgfrom(self,sender,params=None):
    if not self._actions & CHGFROM: raise DisabledAction("CHGFROM")
    return self._ctx.chgfrom(sender,params)

  # When quarantined, a message goes into the mailq as if to be delivered,
  # but delivery is deferred until the message is unquarantined.
  def quarantine(self,reason):
    if not self._actions & QUARANTINE: raise DisabledAction("QUARANTINE")
    return self._ctx.quarantine(reason)

  def progress(self):
    return self._ctx.progress()
  
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

def negotiate_callback(ctx,opts):
  m = factory()
  m._setctx(ctx)
  return m.negotiate(opts)

def connect_callback(ctx,hostname,family,hostaddr,nr_mask=P_NR_CONN):
  m = ctx.getpriv()
  if not m:     
    # If not already created (because the current MTA doesn't support
    # xmfi_negotiate), create the connection object.
    m = factory()
    m._setctx(ctx)
  return m.connect(hostname,family,hostaddr)

def close_callback(ctx):
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
  milter.set_connect_callback(connect_callback)
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
  milter.set_close_callback(close_callback)

  milter.setconn(socketname)
  if timeout > 0: milter.settimeout(timeout)
  # The name *must* match the X line in sendmail.cf (supposedly)
  milter.register(name,
        data=lambda ctx: ctx.getpriv().data(),
        unknown=lambda ctx,cmd: ctx.getpriv().unknown(cmd),
        negotiate=negotiate_callback
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
