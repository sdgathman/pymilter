## @package Milter
# A thin OO wrapper for the milter module.
#
# Clients generally subclass Milter.Base and define callback
# methods.
#
# @author Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2009 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

__version__ = '0.9.8'

import os
import re
import milter
import thread

from milter import *
from functools import wraps

_seq_lock = thread.allocate_lock()
_seq = 0

def uniqueID():
  """Return a unique sequence number (incremented on each call).
  """
  global _seq
  _seq_lock.acquire()
  seqno = _seq = _seq + 1
  _seq_lock.release()
  return seqno

## @private
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

## @private
R = re.compile(r'%+')

## @private
def decode_mask(bits,names):
  t = [ (s,getattr(milter,s)) for s in names]
  nms = [s for s,m in t if bits & m]
  for s,m in t: bits &= ~m
  if bits: nms += hex(bits)
  return nms

## Class decorator to enable optional protocol steps.
# P_SKIP is enabled by default when supported, but
# applications may wish to enable P_HDR_LEADSPC
# to send and receive the leading space of header continuation
# lines unchanged, and/or P_RCPT_REJ to have recipients 
# detected as invalid by the MTA passed to the envcrpt callback.
#
# Applications may want to check whether the protocol is actually
# supported by the MTA in use.  Base._protocol
# is a bitmask of protocol options negotiated.  So,
# for instance, if <code>self._protocol & Milter.P_RCPT_REJ</code>
# is true, then that feature was successfully negotiated with the MTA
# and the application will see recipients the MTA has flagged as invalid.
# 
# Sample use:
# <pre>
# class myMilter(Milter.Base):
#   def envrcpt(self,to,*params):
#     return Milter.CONTINUE
# myMilter = Milter.enable_protocols(myMilter,Milter.P_RCPT_REJ)
# </pre>
# @since 0.9.3
# @param klass the %milter application class to modify
# @param mask a bitmask of protocol steps to enable
# @return the modified %milter class
def enable_protocols(klass,mask):
  klass._protocol_mask = klass.protocol_mask() & ~mask
  return klass

## Milter rejected recipients. A class decorator that calls
# enable_protocols() with the P_RCPT_REJ flag.  By default, the MTA
# does not pass recipients that it knows are invalid on to the milter.
# This decorator enables a %milter app to see all recipients if supported
# by the MTA.  Use like this with python-2.6 and later:
# <pre>
# @@Milter.rejected_recipients
# class myMilter(Milter.Base):
#   def envrcpt(self,to,*params):
#     return Milter.CONTINUE
# </pre>
# @since 0.9.5
# @param klass the %milter application class to modify
# @return the modified %milter class
def rejected_recipients(klass):
  return enable_protocols(klass,P_RCPT_REJ)

## Milter leading space on headers. A class decorator that calls
# enable_protocols() with the P_HEAD_LEADSPC flag.  By default,
# header continuation lines are collected and joined before getting
# sent to a milter.  Headers modified or added by the milter are
# folded by the MTA as necessary according to its own standards.
# With this flag, header continuation lines are preserved
# with their newlines and leading space.  In addition, header folding
# done by the milter is preserved as well.
# Use like this with python-2.6 and later:
# <pre>
# @@Milter.header_leading_space
# class myMilter(Milter.Base):
#   def header(self,hname,value):
#     return Milter.CONTINUE
# </pre>
# @since 0.9.5
# @param klass the %milter application class to modify
# @return the modified %milter class
def header_leading_space(klass):
  return enable_protocols(klass,P_HEAD_LEADSPC)

## Function decorator to disable callback methods.
# If the MTA supports it, tells the MTA not to invoke this callback,
# increasing efficiency.  All the callbacks (except negotiate)
# are disabled in Milter.Base, and overriding them reenables the
# callback.  An application may need to use @@nocallback when it extends
# another %milter and wants to disable a callback again.
# The disabled method should still return Milter.CONTINUE, in case the MTA does
# not support protocol negotiation, and for when called from a test harness.
# @since 0.9.2
def nocallback(func):
  try:
    func.milter_protocol = OPTIONAL_CALLBACKS[func.__name__][1]
  except KeyError:
    raise ValueError(
      '@nocallback applied to non-optional method: '+func.__name__)
  def wrapper(self,*args):
    if func(self,*args) != CONTINUE:
      raise RuntimeError('%s return code must be CONTINUE with @nocallback'
        % func.__name__)
    return CONTINUE
  return wrapper

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
  except KeyError:
    raise ValueError(
      '@noreply applied to non-optional method: '+func.__name__)
  @wraps(func)
  def wrapper(self,*args):
    rc = func(self,*args)
    if self._protocol & nr_mask:
      if rc != CONTINUE:
        raise RuntimeError('%s return code must be CONTINUE with @noreply'
	  % func.__name__)
      return NOREPLY
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

## A do "nothing" Milter base class representing an SMTP connection.
#
# Python milters should derive from this class
# unless they are using the low level milter module directly.  
#
# Most of the methods are either "actions" or "callbacks".  Callbacks
# are invoked by the MTA at certain points in the SMTP protocol.  For
# instance when the HELO command is seen, the MTA calls the helo
# callback before returning a response code.  All callbacks must
# return one of these constants: CONTINUE, TEMPFAIL, REJECT, ACCEPT,
# DISCARD, SKIP.  The NOREPLY response is supplied automatically by
# the @@noreply decorator if negotiation with the MTA is successful.
# @@noreply and @@nocallback methods should return CONTINUE for two reasons:
# the MTA may not support negotiation, and the class may be running in a test
# harness.
# 
# Optional callbacks are disabled with the @@nocallback decorator, and
# automatically reenabled when overridden.  Disabled callbacks should
# still return CONTINUE for testing and MTAs that do not support
# negotiation.  

# Each SMTP connection to the MTA calls the factory method you provide to
# create an instance derived from this class.  This is typically the
# constructor for a class derived from Base.  The _setctx() method attaches
# the instance to the low level milter.milterContext object.  When the SMTP
# connection terminates, the close callback is called, the low level connection
# object is destroyed, and this normally causes instances of this class to be
# garbage collected as well.  The close() method should release any global
# resources held by instances.
# @since 0.9.2
class Base(object):
  "The core class interface to the %milter module."

  ## Attach this Milter to the low level milter.milterContext object.
  def _setctx(self,ctx):
    ## The low level @ref milter.milterContext object.
    self._ctx = ctx
    ## A bitmask of actions this connection has negotiated to use.
    # By default, all actions are enabled.  High throughput milters
    # may want to disable unused actions to increase efficiency.
    # Some optional actions may be disabled by calling milter.set_flags(), or
    # by overriding the negotiate callback.  The bits include:
    # <code>ADDHDRS,CHGBODY,MODBODY,ADDRCPT,ADDRCPT_PAR,DELRCPT
    #  CHGHDRS,QUARANTINE,CHGFROM,SETSYMLIST</code>.
    # The <code>Milter.CURR_ACTS</code> bitmask is all actions
    # known when the milter module was compiled.
    # Application code can also inspect this field to determine
    # which actions are available.  This is especially useful in
    # generic library code designed to work in multiple milters.
    # @since 0.9.2
    #
    self._actions = CURR_ACTS         # all actions enabled by default
    ## A bitmask of protocol options this connection has negotiated.
    # An application may inspect this
    # variable to determine which protocol steps are supported.  Options
    # of interest to applications: the SKIP result code is allowed
    # only if the P_SKIP bit is set, rejected recipients are passed to the
    # %milter application only if the P_RCPT_REJ bit is set, and
    # header values are sent and received with leading spaces (in the
    # continuation lines) intact if the P_HDR_LEADSPC bit is set (so
    # that the application can customize indenting).  
    #
    # The P_N* bits should be negotiated via the @@noreply and @@nocallback
    # method decorators, and P_RCPT_REJ, P_HDR_LEADSPC should
    # be enabled using the enable_protocols class decorator.
    #
    # The bits include: <code>
    # P_RCPT_REJ P_NR_CONN P_NR_HELO P_NR_MAIL P_NR_RCPT P_NR_DATA P_NR_UNKN
    # P_NR_EOH P_NR_BODY P_NR_HDR P_NOCONNECT P_NOHELO P_NOMAIL P_NORCPT
    # P_NODATA P_NOUNKNOWN P_NOEOH P_NOBODY P_NOHDRS P_HDR_LEADSPC P_SKIP
    # </code> (all under the Milter namespace).
    # @since 0.9.2
    self._protocol = 0                # no protocol options by default
    if ctx:
      ctx.setpriv(self)

  ## Defined by subclasses to write log messages.
  def log(self,*msg): pass
  ## Called for each connection to the MTA.  Called by the
  # <a href="https://www.milter.org/developers/api/xxfi_connect">
  # xxfi_connect</a> callback.  
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
  # To vary behavior based on what port the client connected to,
  # for example skipping blacklist checks for port 587 (which must 
  # be authenticated), use @link #getsymval getsymval('{daemon_port}') @endlink.
  # The <code>{daemon_port}</code> macro must be enabled in sendmail.cf
  # <pre>
  # O Milter.macros.connect=j, _, {daemon_name}, {daemon_port}, {if_name}, {if_addr}
  # </pre>
  # or sendmail.mc
  # <pre>
  # define(`confMILTER_MACROS_CONNECT', ``j, _, {daemon_name}, {daemon_port}, {if_name}, {if_addr}'')dnl
  # </pre>
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
  ## Called when the SMTP client says MAIL FROM. Called by the
  # <a href="https://www.milter.org/developers/api/xxfi_envfrom">
  # xxfi_envfrom</a> callback.  
  # Returning REJECT rejects the message, but not the connection.
  # The sender is the "envelope" from as defined by
  # <a href="http://tools.ietf.org/html/rfc5321">RFC 5321</a>.
  # For the From: header (author) defined in 
  # <a href="http://tools.ietf.org/html/rfc5322">RFC 5322</a>,
  # see @link #header the header callback @endlink.
  @nocallback
  def envfrom(self,f,*str): return CONTINUE
  ## Called when the SMTP client says RCPT TO. Called by the
  # <a href="https://www.milter.org/developers/api/xxfi_envrcpt">
  # xxfi_envrcpt</a> callback.
  # Returning REJECT rejects the current recipient, not the entire message.
  # The recipient is the "envelope" recipient as defined by 
  # <a href="http://tools.ietf.org/html/rfc5321">RFC 5321</a>.
  # For recipients defined in 
  # <a href="http://tools.ietf.org/html/rfc5322">RFC 5322</a>, 
  # for example To: or Cc:, see @link #header the header callback @endlink.
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

  ## Return mask of SMFIP_N* protocol option bits to clear for this class
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
    
  ## Negotiate milter protocol options.  Called by the
  # <a href="https://www.milter.org/developers/api/xxfi_negotiate">
  # xffi_negotiate</a> callback.  This is an advanced callback,
  # do not override unless you know what you are doing.  Most
  # negotiation can be done simply by using the supplied 
  # class and function decorators.
  # Options are passed as 
  # a list of 4 32-bit ints which can be modified and are passed
  # back to libmilter on return.
  # Default negotiation sets P_NO* and P_NR* for callbacks
  # marked @@nocallback and @@noreply respectively, leaves all
  # actions enabled, and enables Milter.SKIP.  The @@enable_protocols
  # class decorator can customize which protocol steps are implemented.
  # @param opts a modifiable list of 4 ints with negotiated options
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
  # See <a href="https://www.milter.org/developers/api/smfi_getsymval">
  # smfi_getsymval</a> for default sendmail macros.
  # @param sym the macro name
  def getsymval(self,sym):
    return self._ctx.getsymval(sym)

  ## Set the SMTP reply code and message.
  # If the MTA does not support setmlreply, then only the
  # first msg line is used.  Any '%%' in a message line
  # must be doubled, or libmilter will silently ignore the setreply.
  # Beginning with 0.9.6, we test for that case and throw ValueError to avoid
  # head scratching.  What will <i>really</i> irritate you, however,
  # is that if you carefully double any '%%', your message will be
  # sent - but with the '%%' still doubled!
  # See <a href="https://www.milter.org/developers/api/smfi_setreply">
  # smfi_setreply</a> for more information.
  # @param rcode The three-digit (RFC 821/2821) SMTP reply code as a string. 
  # rcode cannot be None, and <b>must be a valid 4XX or 5XX reply code</b>.
  # @param xcode The extended (RFC 1893/2034) reply code. If xcode is None,
  # no extended code is used. Otherwise, xcode must conform to RFC 1893/2034.
  # @param msg The text part of the SMTP reply. If msg is None,
  # an empty message is used.
  # @param ml  Optional additional message lines.
  def setreply(self,rcode,xcode=None,msg=None,*ml):
    for m in (msg,)+ml:
      if 1 in [len(s)&1 for s in R.findall(m)]:
        raise ValueError("'%' must be doubled: "+m)
    return self._ctx.setreply(rcode,xcode,msg,*ml)

  ## Tell the MTA which macro names will be used.
  # This information can reduce the size of messages received from sendmail,
  # and hence could reduce bandwidth between sendmail and your milter where
  # that is a factor.  The <code>Milter.SETSYMLIST</code> action flag must be
  # set.  The protocol stages are M_CONNECT, M_HELO, M_ENVFROM, M_ENVRCPT,
  # M_DATA, M_EOM, M_EOH.
  #
  # May only be called from negotiate callback.
  # @since 0.9.8, previous version was misspelled!
  # @param stage the protocol stage to set to macro list for, 
  # one of the M_* constants defined in Milter
  # @param macros space separated and/or lists of strings
  def setsymlist(self,stage,*macros):
    if not self._actions & SETSYMLIST: raise DisabledAction("SETSYMLIST")
    a = []
    for m in macros:
      try:
        m = m.encode('utf8')
      except: pass
      try:
        m = m.split(' ')
      except: pass
      a += m
    return self._ctx.setsmlist(stage,' '.join(a))

  # Milter methods which can only be called from eom callback.

  ## Add a mail header field.
  # Calls <a href="https://www.milter.org/developers/api/smfi_addheader">
  # smfi_addheader</a>.  
  # The <code>Milter.ADDHDRS</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param field        the header field name
  # @param value        the header field value
  # @param idx header field index from the top of the message to insert at
  # @throws DisabledAction if ADDHDRS is not enabled
  def addheader(self,field,value,idx=-1):
    if not self._actions & ADDHDRS: raise DisabledAction("ADDHDRS")
    return self._ctx.addheader(field,value,idx)

  ## Change the value of a mail header field.
  # Calls <a href="https://www.milter.org/developers/api/smfi_chgheader">
  # smfi_chgheader</a>.  
  # The <code>Milter.CHGHDRS</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param field the name of the field to change
  # @param idx index of the field to change when there are multiple instances
  # @param value the new value of the field
  # @throws DisabledAction if CHGHDRS is not enabled
  def chgheader(self,field,idx,value):
    if not self._actions & CHGHDRS: raise DisabledAction("CHGHDRS")
    return self._ctx.chgheader(field,idx,value)

  ## Add a recipient to the message.  
  # Calls <a href="https://www.milter.org/developers/api/smfi_addrcpt">
  # smfi_addrcpt</a>.  
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
  # @throws DisabledAction if ADDRCPT or ADDRCPT_PAR is not enabled 
  def addrcpt(self,rcpt,params=None):
    if not self._actions & ADDRCPT: raise DisabledAction("ADDRCPT")
    if params and not self._actions & ADDRCPT_PAR:
        raise DisabledAction("ADDRCPT_PAR")
    return self._ctx.addrcpt(rcpt,params)
  ## Delete a recipient from the message.
  # Calls <a href="https://www.milter.org/developers/api/smfi_delrcpt">
  # smfi_delrcpt</a>.  
  # The recipient should match one passed to the envrcpt callback.
  # The <code>Milter.DELRCPT</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param rcpt the message recipient to delete
  # @throws DisabledAction if DELRCPT is not enabled
  def delrcpt(self,rcpt):
    if not self._actions & DELRCPT: raise DisabledAction("DELRCPT")
    return self._ctx.delrcpt(rcpt)

  ## Replace the message body.
  # Calls <a href="https://www.milter.org/developers/api/smfi_replacebody">
  # smfi_replacebody</a>.  
  # The entire message body must be replaced.  
  # Call repeatedly with blocks of data until the entire body is transferred.
  # The <code>Milter.MODBODY</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param body a chunk of body data
  # @throws DisabledAction if MODBODY is not enabled
  def replacebody(self,body):
    if not self._actions & MODBODY: raise DisabledAction("MODBODY")
    return self._ctx.replacebody(body)

  ## Change the SMTP envelope sender address.
  # Calls <a href="https://www.milter.org/developers/api/smfi_chgfrom">
  # smfi_chgfrom</a>.  
  # The syntax of the sender is that same as used in the SMTP
  # MAIL FROM command (and as delivered to the envfrom callback),
  # for example <code>self.chgfrom('<bar@example.com>')</code>.
  # The <code>Milter.CHGFROM</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @since 0.9.1
  # @param sender the new sender address
  # @param params an optional list of ESMTP parameters
  # @throws DisabledAction if CHGFROM is not enabled
  def chgfrom(self,sender,params=None):
    if not self._actions & CHGFROM: raise DisabledAction("CHGFROM")
    return self._ctx.chgfrom(sender,params)

  ## Quarantine the message.
  # Calls <a href="https://www.milter.org/developers/api/smfi_quarantine">
  # smfi_quarantine</a>.  
  # When quarantined, a message goes into the mailq as if to be delivered,
  # but delivery is deferred until the message is unquarantined.
  # The <code>Milter.QUARANTINE</code> action flag must be set.
  #
  # May be called from eom callback only.
  # @param reason a string describing the reason for quarantine
  # @throws DisabledAction if QUARANTINE is not enabled
  def quarantine(self,reason):
    if not self._actions & QUARANTINE: raise DisabledAction("QUARANTINE")
    return self._ctx.quarantine(reason)

  ## Tell the MTA to wait a bit longer.
  # Calls <a href="https://www.milter.org/developers/api/smfi_progress">
  # smfi_progress</a>.  
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
# @brief Connect context to connection instance and return enabled callbacks.
def negotiate_callback(ctx,opts):
  m = factory()
  m._setctx(ctx)
  return m.negotiate(opts)

## @private
# @brief Connect context if needed and invoke connect method.
def connect_callback(ctx,hostname,family,hostaddr,nr_mask=P_NR_CONN):
  m = ctx.getpriv()
  if not m:     
    # If not already created (because the current MTA doesn't support
    # xmfi_negotiate), create the connection object.
    m = factory()
    m._setctx(ctx)
  return m.connect(hostname,family,hostaddr)

## @private
# @brief Disconnect milterContext and call close method.
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

## Run the %milter.
# @param name the name of the %milter known to the MTA
# @param socketname the socket to be passed to milter.setconn()
# @param timeout the time in secs the MTA should wait for a response before 
#	considering this %milter dead
def runmilter(name,socketname,timeout = 0,rmsock=True):

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

  # We remove the socket here by default on the assumption that you will be
  # starting this filter before sendmail.  If sendmail is not running and the
  # socket already exists, libmilter will throw a warning.  If sendmail is
  # running, this is still safe if there are no messages currently being
  # processed.  It's safer to shutdown sendmail, kill the filter process,
  # restart the filter, and then restart sendmail.
  milter.opensocket(rmsock)
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
## @example milter-nomix.py
#
