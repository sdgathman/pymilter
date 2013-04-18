# Document miltermodule for Doxygen
#

## @package milter
#
# A thin wrapper around libmilter.  Most users will not import
# milter directly, but will instead import Milter and subclass
# Milter.Base.  This module gives you ultimate low level control
# from python.
#

## Continue processing the current connection, message, or recipient.
CONTINUE  = 0
##  For a connection-oriented routine, reject this connection; 
# call Milter.Base.close(). For a message-oriented routine, except
# Milter.Base.eom() or Milter.Base.abort(), reject this message.  For a
# recipient-oriented routine, reject the current recipient (but continue
# processing the current message).
REJECT    = 1

## For a message- or recipient-oriented routine, accept this message, but
# silently discard it.  SMFIS_DISCARD should not be returned by a
# connection-oriented routine.
DISCARD   = 2

## For a connection-oriented routine, accept this connection without further
# filter processing; call Milter.Base.close().   For a message- or
# recipient-oriented routine, accept this message without further filtering.
ACCEPT    = 3

## Return a temporary failure, i.e., the corresponding SMTP command will return
# an appropriate 4xx status code. For a message-oriented routine, except
# Milter.Base.envfrom(), fail for this message.  For a connection-oriented
# routine, fail for this connection; call Milter.Base.close().  For a recipient-oriented
# routine, only
# fail for the current recipient; continue message processing.
TEMPFAIL  = 4

## Skip further callbacks of the same type in this transaction. 
# Currently this return value is only allowed in Milter.Base.body(). It can be
# used if a %milter has received sufficiently many body chunks to make a
# decision, but still wants to invoke message modification functions that are
# only allowed to be called from Milter.Base.eom(). Note: the %milter must
# negotiate this behavior with the MTA, i.e., it must check whether the
# protocol action SMFIP_SKIP is available and if so, the %milter must request
# it.
SKIP      = 5

## Do not send a reply back to the MTA. 
# The %milter must negotiate this behavior with the MTA, i.e., it must check
# whether the appropriate protocol action P_NR_* is available and if so,
# the %milter must request it. If you set the P_NR_* protocol action for a
# callback, that callback must always reply with NOREPLY. Using any other
# reply code is a violation of the API. If in some cases your callback may
# return another value (e.g., due to some resource shortages), then you must
# not set P_NR_* and you must use CONTINUE as the default return
# code. (Alternatively you can try to delay reporting the problem to a later
# callback for which P_NR_* is not set.)
#
# This is negotiated and returned automatically by the Milter.noreply 
# function decorator.
NOREPLY   = 6

## Hold context for a %milter connection.
# Each connection to sendmail creates a new <code>SMFICTX</code> struct within
# libmilter.  The milter module in turn creates a milterContext
# tied to the <code>SMFICTX</code> struct via <code>smfi_setpriv</code>
# to hold a PyThreadState and a user defined Python object for the connection.
# 
# Most application interaction with libmilter takes places via 
# the milterContext object for the connection.  It is passed to
# callback functions as the first parameter.
#
# The <code>Milter</code> module creates a python class for each connection,
# and converts function callbacks to instance method invocations.
#
class milterContext(object):
  ## Calls <a href="https://www.milter.org/developers/api/smfi_getsymval">smfi_getsymval</a>.
  def getsymval(self,sym): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_setreply">
  # smfi_setreply</a> or
  # <a href="https://www.milter.org/developers/api/smfi_setmlreply">
  # smfi_setmlreply</a>.
  # @param rcode SMTP response code
  # @param xcode extended SMTP response code
  # @param msg one or more message lines.  If the MTA does not support 
  #     multiline messages, only the first is used.
  def setreply(self,rcode,xcode,*msg): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_addheader">smfi_addheader</a>.
  def addheader(self,name,value,idx=-1): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_chgheader">smfi_chgheader</a>.
  def chgheader(self,name,idx,value): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_addrcpt">smfi_addrcpt</a>.
  def addrcpt(self,rcpt,params=None): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_delrcpt">smfi_delrcpt</a>.
  def delrcpt(self,rcpt): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_replacebody">smfi_replacebody</a>.
  def replacebody(self,data): pass
  ## Attach a Python object to this connection context.
  # @return the old value or None
  def setpriv(self,priv): pass
  ## Return the Python object attached to this connection context.
  def getpriv(self): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_quarantine">smfi_quarantine</a>.
  def quarantine(self,reason): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_progress">smfi_progress</a>.
  def progress(self): pass
  ## Calls <a href="https://www.milter.org/developers/api/smfi_chgfrom">smfi_chgfrom</a>.
  def chgfrom(self,sender,param=None): pass
  ## Tell the MTA which macro values we are interested in for a given stage.
  # Of interest only when you need to squeeze a few more bytes of bandwidth.
  # It may only be called from the negotiate callback.
  # The protocol stages are 
  # M_CONNECT, M_HELO, M_ENVFROM, M_ENVRCPT, M_DATA, M_EOM, M_EOH.
  # Calls <a href="https://www.milter.org/developers/api/smfi_setsymlist">smfi_setsymlist</a>.
  # @param stage protocol stage in which the macro list should be used
  # @param macrolist a space separated list of macro names
  def setsymlist(self,stage,macrolist): pass

class error(Exception): pass

## Enable optional %milter actions.
# Certain %milter actions need to be enabled before calling main()
# or they throw an exception.  Pymilter enables them all by
# default (since 0.9.2), but you may wish to disable unneeded
# actions as an optimization.
# @param flags Bit or mask of optional actions to enable
def set_flags(flags): pass

def set_connect_callback(cb): pass
def set_helo_callback(cb): pass
def set_envfrom_callback(cb): pass
def set_envrcpt_callback(cb): pass
def set_header_callback(cb): pass
def set_eoh_callback(cb): pass
def set_body_callback(cb): pass
def set_abort_callback(cb): pass
def set_close_callback(cb): pass

## Sets the return code for untrapped Python exceptions during a callback.
# The default is TEMPFAIL.  You should not depend on this handler.  Your
# application should have its own top level exception handler for each
# callback.  You can then choose your own reply message, log the stack track
# were you please, and so on.  However, if you miss one, this last ditch
# handler will print a standard stack trace to sys.stderr, and return to
# sendmail.  
# @param code one of #TEMPFAIL,#REJECT,#CONTINUE, or since 1.0, #ACCEPT
def set_exception_policy(code): pass

## Register python %milter with libmilter.
# The name we pass is used to identify the %milter in the MTA configuration.
# Callback functions must be set using the set_*_callback() functions before
# registering the %milter.
# Three additional callbacks are specified as keyword parameters.  These
# were added by recent versions of libmilter.  The keyword parameters is
# a nicer way to do it, I think, since it makes clear that you have to do
# it before registering.  I may move all the callbacks in the future (perhaps
# keeping the set functions for compatibility).  Note that Milter.Base
# automatically maps all callbacks to member functions, and negotiates which
# member functions are actually overridden by an application class.
# @param name the %milter name by which the MTA finds us
# @param negotiate the
#       <a href="https://www.milter.org/developers/api/xxfi_negotiate">
#       xxfi_negotiate</a> callback, called to negotiate supported
#       actions, callbacks, and protocol steps.
# @param unknown the
#       <a href="https://www.milter.org/developers/api/xxfi_unknown">
#       xxfi_unknown</a> callback, called when for SMTP commands
#       not recognized by the MTA. (Extend SMTP in your milter!)
# @param data the
#       <a href="https://www.milter.org/developers/api/xxfi_data">
#       xxfi_data</a> callback, called when the DATA
#       SMTP command is received.
def register(name,negotiate=None,unknown=None,data=None): pass

## Attempt to create the socket used to communicate with the MTA.
# milter.opensocket() attempts to create the socket specified previously by a
# call to milter.setconn() which will be the interface between MTAs and the
# %milter.  This allows the calling application to ensure that the socket can be
# created.  If this is not called, milter.main() will do so implicitly.
# Calls <a href="https://www.milter.org/developers/api/smfi_opensocket">
# smfi_opensocket</a>.  While not documented for libmilter, my experiments
# indicate that you must call register() before calling opensocket().
# @param rmsock Try to remove an existing unix domain socket if true.
def opensocket(rmsock): pass

## Transfer control to libmilter.
# Calls <a href="https://www.milter.org/developers/api/smfi_main">
#   smfi_main</a>.
def main(): pass

## Set the libmilter debugging level.
# <a href="https://www.milter.org/developers/api/smfi_setdbg">smfi_setdbg</a>
# sets the %milter library's internal debugging level to a new level
# so that code details may be traced. A level of zero turns off debugging. The
# greater (more positive) the level the more detailed the debugging. Six is the
# current, highest, useful value.  Must be called before calling main().
def setdbg(lev): pass

## Set timeout for MTA communication.
# Calls <a href="https://www.milter.org/developers/api/smfi_settimeout">
# smfi_settimeout</a>.  Must be called before calling main().
def settimeout(secs): pass

## Set socket backlog.
# Calls <a href="https://www.milter.org/developers/api/smfi_setbacklog">
# smfi_setbacklog</a>.  Must be called before calling main().
def setbacklog(n): pass

## Set the socket used to communicate with the MTA.
# The MTA can communicate with the milter by means of a
# unix, inet, or inet6 socket. By default, a unix domain socket
# is used.  It must not exist,
# and sendmail will throw warnings if, eg, the file is under a
# group or world writable directory.  milter.setconn() will not fail with
# an invalid socket - this will be detected only when calling milter.main()
# or milter.opensocket().
# @param s the socket address in proto:address format
# <pre>
# milter.setconn('unix:/var/run/pythonfilter')  # a named pipe
# milter.setconn('local:/var/run/pythonfilter') # a named pipe
# milter.setconn('inet:8800') 			# listen on ANY interface
# milter.setconn('inet:7871@@publichost')	# listen on a specific interface
# milter.setconn('inet6:8020')
# milter.setconn('inet6:8020@[2001:db8:1234::1]')      # listen on specific IP
# </pre>
def setconn(s): pass

## Stop the %milter gracefully.
def stop(): pass

## Retrieve diagnostic info.
# Return a tuple with diagnostic info gathered by the milter module.
# The first two fields are counts of milterContext objects created
# and deleted.  Additional fields may be added later.
# @return a tuple of diagnostic data
def getdiag(): pass

## Retrieve the runtime libmilter version.
# Return the runtime libmilter version. This can be different
# from the compile time version when sendmail or libmilter is upgraded
# after pymilter is compiled.
# @return a tuple of <code>(major,minor,patchlevel)</code>
def getversion(): pass

## The compile time libmilter version.
# Python code might need to deal with pymilter compiled 
# against various versions of libmilter.  This module constant 
# contains the contents of the <code>SMFI_VERSION</code> macro when
# the milter module was compiled.
VERSION = 0x1000001
