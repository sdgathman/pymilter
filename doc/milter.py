# Document miltermodule for Doxygen
#

## @package milter
#
# A thin wrapper around libmilter.
#

## Hold context for a milter connection.
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
  def getsymval(self,sym): pass
  def setreply(self,rcode,xcode,*msg): pass
  def addheader(self,name,value,idx=-1): pass
  def chgheader(self,name,idx,value): pass
  def addrcpt(self,rcpt,params=None): pass
  def delrcpt(self,rcpt): pass
  def replacebody(self,data): pass
  def setpriv(self,priv): pass
  def getpriv(self): pass
  def quarantine(self,reason): pass
  def progress(self): pass
  def chgfrom(self,sender,param=None): pass
  def setsmlist(self,stage,macrolist): pass

class error(Exception): pass

## Enable optional milter actions.
# Certain milter actions need to be enabled before calling milter.runmilter()
# or they throw an exception. 
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
def set_exception_policy(code): pass
## Register python milter with libmilter.
# The name we pass is used to identify the milter in the MTA configuration.
# Callback functions must be set using the set_*_callback() functions before
# registering the milter.
# Three additional callbacks are specified as keyword parameters.  These
# were added by recent versions of libmilter.  The keyword parameters is
# a nicer way to do it, I think, since it makes clear that you have to do
# it before registering.  I may move all the callbacks 
# in the future (perhaps keeping the set functions for compatibility).
# @param name the milter name by which the MTA finds us
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
def opensocket(rmsock): pass
def main(): pass

## Set the libmilter debugging level.
# smfi_setdbg sets the milter library's internal debugging level to a new level
# so that code details may be traced. A level of zero turns off debugging. The
# greater (more positive) the level the more detailed the debugging. Six is the
# current, highest, useful value.
def setdbg(lev): pass

def settimeout(secs): pass
def setbacklog(n): pass

## Set the socket used to communicate with the MTA.
# The MTA can communicate with the milter by means of a
# unix, inet, or inet6 socket. By default, a unix domain socket
# is used.  It must not exist,
# and sendmail will throw warnings if, eg, the file is under a
# group or world writable directory.
# <pre>
# setconn('unix:/var/run/pythonfilter')
# setconn('inet:8800') 			# listen on ANY interface
# setconn('inet:7871@@publichost')	# listen on a specific interface
# setconn('inet6:8020')
# </pre>
def setconn(s): pass

## Stop the milter gracefully.
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
