# Document miltermodule for Doxygen
#

## @package milter
#
# A thin wrapper around libmilter.
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
def register(name,negotiate=None,unknown=None,data=None): pass
def opensocket(rmsock): pass
def main(): pass
def setdbg(lev): pass
def settimeout(secs): pass
def setbacklog(n): pass
def setconn(s): pass
def stop(): pass
