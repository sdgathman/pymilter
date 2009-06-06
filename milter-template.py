## To roll your own milter, create a class that extends Milter.  
#  See the pymilter project at http://bmsi.com/python/milter.html
#  based on Sendmail's milter API http://www.milter.org/milter_api/api.html
#  This code is open-source on the same terms as Python.

## Milter calls methods of your class at milter events.
## Return REJECT,TEMPFAIL,ACCEPT to short circuit processing for a message.
## You can also add/del recipients, replacebody, add/del headers, etc.

import Milter
import StringIO
import time
import email
from socket import AF_INET, AF_INET6
from Milter import parse_addr


class myMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.

  # each connection runs in its own thread and has its own myMilter
  # instance.  Python code must be thread safe.  This is trivial if only stuff
  # in myMilter instances is referenced.
  @noreply
  def connect(self, IPname, family, hostaddr):
    # (self, 'ip068.subnet71.example.com', AF_INET, ('215.183.71.68', 4720) )
    # (self, 'ip6.mxout.example.com', AF_INET6,
    #	('3ffe:80e8:d8::1', 4720, 1, 0) )
    self.IP = hostaddr[0]
    self.port = hostaddr[1]
    if family == AF_INET6:
      self.flow = hostaddr[2]
      self.scope = hostaddr[3]
    else:
      self.flow = None
      self.scope = None
    self.IPname = IPname  # Name from a reverse IP lookup
    self.H = None
    self.fp = None
    self.receiver = self.getsymval('j')
    self.log("connect from %s at %s" % (IPname, hostaddr) )
    
    return Milter.CONTINUE


  ##  def hello(self,hostname):
  def hello(self, heloname):
    # (self, 'mailout17.dallas.texas.example.com')
    self.H = heloname
    self.log("HELO %s" % heloname)
    if heloname.find('.') < 0:	# illegal helo name
      # NOTE: example only - too many real braindead clients to reject on this
      self.setreply('550','5.7.1','Sheesh people!  Use a proper helo name!')
      return Milter.REJECT
      
    return Milter.CONTINUE

  ##  def envfrom(self,f,*str):
  def envfrom(self, mailfrom, *str):
    self.F = mailfrom
    self.R = []  # list of recipients
    self.fromparms = Milter.dictfromlist(str)	# ESMTP parms
    self.user = self.getsymval('{auth_authen}')	# authenticated user
    self.log("mail from:", mailfrom, *str)
    self.fp = StringIO.StringIO()
    self.canon_from = '@'.join(parse_addr(mailfrom))
    self.fp.write('From %s %s\n' % (self.canon_from,time.ctime()))
    return Milter.CONTINUE


  ##  def envrcpt(self, to, *str):
  @noreply
  def envrcpt(self, recipient, *str):
    rcptinfo = to,Milter.dictfromlist(str)
    self.R.append(rcptinfo)
    
    return Milter.CONTINUE


  @noreply
  def header(self, name, hval):
    self.fp.write("%s: %s\n" % (name,hval))	# add header to buffer
    return Milter.CONTINUE

  @noreply
  def eoh(self):
    self.fp.write("\n")				# terminate headers
    return Milter.CONTINUE

  @noreply
  def body(self, chunk):
    self.fp.write(chunk)
    return Milter.CONTINUE

  def eom(self):
    self.fp.seek(0)
    msg = email.message_from_file(self.fp)
    self.setreply('250','2.5.1','Grokked by pymilter')
    # many milter functions can only be called from eom()
    # example of adding a Bcc:
    self.addrcpt('<%s>' % 'spy@example.com')
    return Milter.ACCEPT


  def close(self):
    # always called, even when abort is called.  Clean up
    # any external resources here.
    return Milter.CONTINUE

  def abort(self):
    # client disconnected prematurely
    return Milter.CONTINUE

  ## === Support Functions ===

  def log(self,*msg):
    print "%s [%d]" % (time.strftime('%Y%b%d %H:%M:%S'),self.id),
    # 2005Oct13 02:34:11 [1] msg1 msg2 msg3 ...
    for i in msg: print i,
    print


## ===
    
def main():
  # Register to have the Milter factory create instances of your class:
  Milter.factory = myMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  flags += Milter.ADDRCPT
  flags += Milter.DELRCPT
  Milter.set_flags(flags)       # tell Sendmail which features we use
  print "%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,timeout)
  print "%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()
