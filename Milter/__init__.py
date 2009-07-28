## @package Milter
# A thin OO wrapper for the milter module.
#
# Clients generally subclass Milter.Base and define callback
# methods.
#
# @author Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2009 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

__version__ = '0.9.3'

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

def decode_mask(bits,names):
  t = [ (s,getattr(milter,s)) for s in names]
  nms = [s for s,m in t if bits & m]
  for s,m in t: bits &= ~m
  if bits: nms += hex(bits)
  return nms

## Class decorator to enable optional protocol steps.
# P_SKIP is enabled by default when supported, but
# milter applications may wish to enable P_HDR_LEADSPC
# to send and receive the leading space of header continuation
# lines unchanged, and/or P_RCPT_REJ to have recipients 
# detected as invalid by the MTA passed to the envcrpt callback.
#
# Applications may want to check whether the protocol is actually
# supported by the MTA in use.  The <code>_protocol</code> 
# member is a bitmask of protocol options negotiated.  So,
# for instance, if <code>self._protocol & Milter.P_RCPT_REJ</code>
# is true, then that feature was successfully negotiated with the MTA.
# 
# Sample use:
# <pre>
# class myMilter(Milter.Base):
#   def envrcpt(self,to,*params):
#     return Milter.CONTINUE
# myMilter = Milter.enable_protocols(myMilter,Milter.P_RCPT_REJ)
# </pre>
# @since 0.9.3
# @param klass the milter application class to modify
# @param mask a bitmask of protocol steps to enable
# @return the modified milter class
def enable_protocols(klass,mask):
  klass._protocol_mask = klass.protocol_mask() & ~mask
  return klass

## Function decorator to disable callback methods.
# If the MTA supports it, tells the MTA not to call this callback,
# increasing efficiency.  All the callbacks (except negotiate)
# are disabled in Milter.Base, and overriding them reenables the
# callback.  An application may need to use @@callback when it extends
# another milter and wants to disable a callback again.
# The disabled method should still return Milter.CONTINUE, in case the MTA does
# not support protocol negotiation.
# @since 0.9.2
def nocallback(func):
  try:
    func.milter_protocol = OPTIONAL_CALLBACKS[func.__name__][1]
  except KeyError:
    raise ValueError(
      '@nocallback applied to non-optional method: '+func.__name__)
  return func

## Function decorator to disable callback reply.
# If the MTA supports it, tells the MTA not to wait for a reply from
# this callback, and assume CONTINUE.  The method should still return
# CONTINUE in case the MTA does not support protocol negotiation.
# The decorator arranges to change the return code to NOREPLY 
# when supported by the MTA.
# @since 0.9.2
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

## Disabled action exception.
# set_flags() can tell the MTA that this application will not use certain
# features (such as CHGFROM).  This can also be negotiated for each
# connection in the negotiate callback.  If the application then calls
# the feature anyway via an instance method, this exception is
# thrown.
# @since 0.9.2
class DisabledAction(RuntimeError):
  pass

## A do "nothing" Milter base class.
# Python milters should derive from this class
# unless they are using the low lever milter module directly.  
# All optional callbacks are disabled, and automatically
# reenabled when overridden.
# @since 0.9.2
class Base(object):
  "The core class interface to the milter module."

  ## Attach this Milter to the low level milter.milterContext object.
  def _setctx(self,ctx):
    self._ctx = ctx
    self._actions = CURR_ACTS         # all actions enabled by default
    self._protocol = 0                # no protocol options by default
    if ctx:
      ctx.setpriv(self)
  ## @var _actions
  # A bitmask of actions this milter has negotiated to use.
  # By default, all actions are enabled.  This may be changed
  # by calling <code>milter.set_flags</code>, or by overriding
  # the negotiate callback.  The bits include:
  # <code>ADDHDRS,CHGBODY,MODBODY,ADDRCPT,ADDRCPT_PAR,DELRCPT
  #  CHGHDRS,QUARANTINE,CHGFROM,SETSMLIST</code>.
  # The <code>Milter.CURR_ACTS</code> bitmask is all actions
  # known when the milter module was compiled.
  # @since 0.9.2
  #

  ## @var _protocol
  # A bitmask of protocol options this milter has negotiated.
  # The bits generally indicate that a particular step should be
  # skipped, since previous versions of the milter protocol had
  # no provision for skipping steps.
  # The bits include: <code>
  # P_RCPT_REJ P_NR_CONN P_NR_HELO P_NR_MAIL P_NR_RCPT P_NR_DATA P_NR_UNKN
  # P_NR_EOH P_NR_BODY P_NR_HDR P_NOCONNECT P_NOHELO P_NOMAIL P_NORCPT
  # P_NODATA P_NOUNKNOWN P_NOEOH P_NOBODY P_NOHDRS P_HDR_LEADSPC P_SKIP
  # </code> (all under the Milter namespace).
  # @since 0.9.2

  ## Defined by subclasses to write log messages.
  def log(self,*msg): pass
  ## Called for each connection to the MTA.
  # The <code>hostname</code> provided by the local MTA is either
  # the PTR name or the IP in the form "[1.2.3.4]" if no PTR is available.
  # The format of hostaddr depends on the socket family:
  # <dl>
  # <dt><code>socket.AF_INET</code>
  # <dd>A tuple of (IP as string in dotted quad form, integer port)
  # <dt><code>socket.AF_INET6</code>
  # <dd>A tuple of (IP as a string in standard representation,
  # integer port, integer flow info, integer scope id)
  # <dt><code>socket.AF_UNIX</code>
  # <dd>A string with the socketname
  # </dl>
  # @param hostname the PTR name or bracketed IP of the SMTP client
  # @param family <code>socket.AF_INET</code>, <code>socket.AF_INET6</code>,
  #     or <code>socket.AF_UNIX</code>
  # @param hostaddr a tuple or string with peer IP or socketname
  @nocallback
  def connect(self,hostname,family,hostaddr): return CONTINUE
  ## Called when the SMTP client says HELO.
  # Returning REJECT prevents progress until a valid HELO is provided;
  # this almost always results in terminating the connection.
  @nocallback
  def hello(self,hostname): return CONTINUE
  ## Called when the SMTP client says MAIL FROM.
  # Returning REJECT rejects the message, but not the connection.
  @nocallback
  def envfrom(self,f,*str): return CONTINUE
  ## Called when the SMTP client says RCPT TO.
  # Returning REJECT rejects the current recipient, not the entire message.
  @nocallback
  def envrcpt(self,to,*str): return CONTINUE
  ## Called when the SMTP client says DATA.
  # Returning REJECT rejects the message without wasting bandwidth
  # on the unwanted message.
  # @since 0.9.2
  @nocallback
  def data(self): return CONTINUE
  ## Called for each header field in the message body.
  @nocallback
  def header(self,field,value): return CONTINUE
  ## Called at the blank line that terminates the header fields.
  @nocallback
  def eoh(self): return CONTINUE
  ## Called to supply the body of the message to the Milter by chunks.
  # @param blk a block of message bytes
  @nocallback
  def body(self,blk): return CONTINUE
  ## Called when the SMTP client issues an unknown command.
  # @param cmd the unknown command
  # @since 0.9.2
  @nocallback
  def unknown(self,cmd): return CONTINUE
  ## Called at the end of the message body.
  # Most of the message manipulation actions can only take place from
  # the eom callback.
  def eom(self): return CONTINUE
  ## Called when the connection is abnormally terminated.
  # The close callback is still called also.
  def abort(self): return CONTINUE
  ## Called when the connection is closed.
  def close(self): return CONTINUE

  ## Return mask of SMFIP_N.. protocol option bits to clear for this class
  # The @@nocallback and @@noreply decorators set the
  # <code>milter_protocol</code> function attribute to the protocol mask bit to
  # pass to libmilter, causing that callback or its reply to be skipped.
  # Overriding a method creates a new function object, so that 
  # <code>milter_protocol</code> defaults to 0.
  # Libmilter passes the protocol bits that the current MTA knows
  # how to skip.  We clear the ones we don't want to skip.
  # The negation is somewhat mind bending, but it is simple.
  # @since 0.9.2
  @classmethod
  def protocol_mask(klass):
    try:
      return klass._protocol_mask
    except AttributeError:
      p = P_RCPT_REJ | P_HDR_LEADSPC    # turn these new features off by default
      for func,(nr,nc) in OPTIONAL_CALLBACKS.items():
        func = getattr(klass,func)
        ca = getattr(func,'milter_protocol',0)
        #print func,hex(nr),hex(nc),hex(ca)
        p |= (nr|nc) & ~ca
      klass._protocol_mask = p
      return p
    
  ## Negotiate milter protocol options.
  # Default negotiation sets P_NO* and P_NR* for callbacks
  # marked @@nocallback and @@noreply respectively, leaves all
  # actions enabled, and enables Milter.SKIP.
  # @since 0.9.2
  def negotiate(self,opts):
    try:
      self._actions,p,f1,f2 = opts
      opts[1] = self._protocol = p & ~self.protocol_mask()
      opts[2] = 0
      opts[3] = 0
      #self.log("Negotiated:",opts)
    except:
      # don't change anything if something went wrong
      return ALL_OPTS 
    return CONTINUE

  # Milter methods which can be invoked from most callbacks

  ## Return the value of an MTA macro.  Sendmail macro names
  # are either single chars (e.g. "j") or multiple chars enclosed
  # in braces (e.g. "{auth_type}").  Macro names are MTA dependent.
  # @param sym the macro name
  def getsymval(self,sym):
    return self._ctx.getsymval(sym)

  ## Set the SMTP reply code and message.
  # If the MTA does not support setmlreply, then only the
  # first msg line is used.
  def setreply(self,rcode,xcode=None,msg=None,*ml):
    return self._ctx.setreply(rcode,xcode,msg,*ml)

  ## Tell the MTA which macro names will be used.
  # The <code>Milter.SETSMLIST</code> action flag must be set.
  #
  # May only be called from negotiate callback.
  # @since 0.9.2
  # @param stage the protocol stage to set to macro list for
  # @param macros a string with a space delimited list of macros
  def setsmlist(self,stage,macros):
    if not self._actions & SETSMLIST: raise DisabledAction("SETSMLIST")
    if type(macros) in (list,tuple):
      macros = ' '.join(macros)
    return self._ctx.setsmlist(stage,macros)

  # Milter methods which can only be called from eom callback.

  ## Add a mail header field.
  # The <code>Milter.ADDHDRS</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param field        the header field name
  # @param value        the header field value
  # @param idx header field index from the top of the message to insert at
  def addheader(self,field,value,idx=-1):
    if not self._actions & ADDHDRS: raise DisabledAction("ADDHDRS")
    return self._ctx.addheader(field,value,idx)

  ## Change the value of a mail header field.
  # The <code>Milter.CHGHDRS</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param field the name of the field to change
  # @param idx index of the field to change when there are multiple instances
  # @param value the new value of the field
  def chgheader(self,field,idx,value):
    if not self._actions & CHGHDRS: raise DisabledAction("CHGHDRS")
    return self._ctx.chgheader(field,idx,value)

  ## Add a recipient to the message.
  # If no corresponding mail header is added, this is like a Bcc.
  # The syntax of the recipient is the same as used in the SMTP
  # RCPT TO command (and as delivered to the envrcpt callback), for example
  # "self.addrcpt('<foo@example.com>')".  
  # The <code>Milter.ADDRCPT</code> action flag must be set.
  # If the optional <code>params</code> argument is used, then
  # the <code>Milter.ADDRCPT_PAR</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param rcpt the message recipient 
  # @param params an optional list of ESMTP parameters
  def addrcpt(self,rcpt,params=None):
    if not self._actions & ADDRCPT: raise DisabledAction("ADDRCPT")
    if params and not self._actions & ADDRCPT_PAR:
        raise DisabledAction("ADDRCPT_PAR")
    return self._ctx.addrcpt(rcpt,params)
  ## Delete a recipient from the message.
  # The recipient should match one passed to the envrcpt callback.
  # The <code>Milter.DELRCPT</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param rcpt the message recipient to delete
  def delrcpt(self,rcpt):
    if not self._actions & DELRCPT: raise DisabledAction("DELRCPT")
    return self._ctx.delrcpt(rcpt)

  ## Replace the message body.
  # The entire message body must be replaced.  
  # Call repeatedly with blocks of data until the entire body is transferred.
  # The <code>Milter.MODBODY</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param body a chunk of body data
  def replacebody(self,body):
    if not self._actions & MODBODY: raise DisabledAction("MODBODY")
    return self._ctx.replacebody(body)

  ## Change the SMTP envelope sender address.
  # The syntax of the sender is that same as used in the SMTP
  # MAIL FROM command (and as delivered to the envfrom callback),
  # for example <code>self.chgfrom('<bar@example.com>')</code>.
  # The <code>Milter.CHGFROM</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @since 0.9.1
  # @param sender the new sender address
  # @param params an optional list of ESMTP parameters
  def chgfrom(self,sender,params=None):
    if not self._actions & CHGFROM: raise DisabledAction("CHGFROM")
    return self._ctx.chgfrom(sender,params)

  ## Quarantine the message.
  # When quarantined, a message goes into the mailq as if to be delivered,
  # but delivery is deferred until the message is unquarantined.
  # The <code>Milter.QUARANTINE</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param reason a string describing the reason for quarantine
  def quarantine(self,reason):
    if not self._actions & QUARANTINE: raise DisabledAction("QUARANTINE")
    return self._ctx.quarantine(reason)

  ## Tell the MTA to wait a bit longer.
  # Resets timeouts in the MTA that detect a "hung" milter.
  def progress(self):
    return self._ctx.progress()
  
## A logging but otherwise do nothing Milter base class.
# This is included for compatibility with previous versions of pymilter.
# The logging callbacks are marked @@noreply.
class Milter(Base):
  "A simple class interface to the milter module."

  ## Provide simple logging to sys.stdout
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

## The milter connection factory
# This factory method is called for each connection to create the
# python object that tracks the connection.  It should return
# an object derived from Milter.Base.
#
# Note that since python is dynamic, this variable can be changed while
# the milter is running: for instance, to a new subclass based on a 
# change in configuration.
factory = Milter

## @private
def negotiate_callback(ctx,opts):
  m = factory()
  m._setctx(ctx)
  return m.negotiate(opts)

## @private
def connect_callback(ctx,hostname,family,hostaddr,nr_mask=P_NR_CONN):
  m = ctx.getpriv()
  if not m:     
    # If not already created (because the current MTA doesn't support
    # xmfi_negotiate), create the connection object.
    m = factory()
    m._setctx(ctx)
  return m.connect(hostname,family,hostaddr)

## @private
def close_callback(ctx):
  m = ctx.getpriv()
  if not m: return CONTINUE
  try:
    rc = m.close()
  finally:
    m._setctx(None)	# release milterContext
  return rc

## Convert ESMTP parameters with values to a keyword dictionary.
# @deprecated You probably want Milter.param2dict instead.
def dictfromlist(args):
  "Convert ESMTP parms with values to keyword dictionary."
  kw = {}
  for s in args:
    pos = s.find('=')
    if pos > 0:
      kw[s[:pos].upper()] = s[pos+1:]
  return kw

## Convert ESMTP parm list to keyword dictionary.
# Params with no value are set to None in the dictionary.
# @since 0.9.3
# @param str list of param strings of the form "NAME" or "NAME=VALUE"
# @return a dictionary of ESMTP param names and values
def param2dict(str): 
  "Convert ESMTP parm list to keyword dictionary."
  pairs = [x.split('=',1) for x in str]
  for e in pairs:
    if len(e) < 2: e.append(None)
  return dict([(k.upper(),v) for k,v in pairs])
  
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

## Run the milter.
# @param name the name of the milter known by the MTA
# @param socketname the socket to be passed to <code>milter.setconn</code>
# @param timeout the time in secs the MTA should wait for a response before 
#	considering this milter dead
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
  # disable negotiate callback if runtime version < (1,0,1)
  ncb = negotiate_callback
  if milter.getversion() < (1,0,1):
    ncb = None
  # The name *must* match the X line in sendmail.cf (supposedly)
  milter.register(name,
        data=lambda ctx: ctx.getpriv().data(),
        unknown=lambda ctx,cmd: ctx.getpriv().unknown(cmd),
        negotiate=ncb
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

## @example milter-template.py
#
