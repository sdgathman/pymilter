## To roll your own milter, create a class that extends Milter.  
#  This is a useless example to show basic features of Milter. 
#  See the pymilter project at https://pymilter.org based 
#  on Sendmail's milter API 
#  This code is open-source on the same terms as Python.

## Milter calls methods of your class at milter events.
## Return REJECT,TEMPFAIL,ACCEPT to short circuit processing for a message.
## You can also add/del recipients, replacebody, add/del headers, etc.

from __future__ import print_function
import Milter
try:
  from StringIO import StringIO as BytesIO
except:
  from io import BytesIO
import time
import email
import sys
import os
from socket import AF_INET, AF_INET6
from Milter.utils import parse_addr
if True:
  # for logging process - usually not needed
  from multiprocessing import Process as Thread, Queue
else:
  from threading import Thread
  from Queue import Queue

logq = None

class myMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.

  # each connection runs in its own thread and has its own myMilter
  # instance.  Python code must be thread safe.  This is trivial if only stuff
  # in myMilter instances is referenced.
  @Milter.noreply
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
    # NOTE: self.fp is only an *internal* copy of message data.  You
    # must use addheader, chgheader, replacebody to change the message
    # on the MTA.
    self.fp = BytesIO()
    self.canon_from = '@'.join(parse_addr(mailfrom))
    self.fp.write(b'From %s %s\n' % (self.canon_from.encode(),
        time.ctime().encode()))
    return Milter.CONTINUE


  ##  def envrcpt(self, to, *str):
  @Milter.noreply
  def envrcpt(self, to, *str):
    rcptinfo = to,Milter.dictfromlist(str)
    self.R.append(rcptinfo)
    
    return Milter.CONTINUE


  @Milter.noreply
  def header(self, name, hval):
    self.fp.write(b'%s: %s\n' % (name.encode(),hval.encode()))	# add header to buffer
    return Milter.CONTINUE

  @Milter.noreply
  def eoh(self):
    self.fp.write(b'\n')				# terminate headers
    return Milter.CONTINUE

  @Milter.noreply
  def body(self, chunk):
    self.fp.write(chunk)
    return Milter.CONTINUE

  def eom(self):
    self.fp.seek(0)
    msg = email.message_from_binary_file(self.fp)
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
    t = (msg,self.id,time.time())
    if logq:
      logq.put(t)
    else:
      # logmsg(*t)
      pass

def logmsg(msg,id,ts):
    print("%s [%d]" % (time.strftime('%Y%b%d %H:%M:%S',time.localtime(ts)),id),
        end=None)
    # 2005Oct13 02:34:11 [1] msg1 msg2 msg3 ...
    for i in msg: print(i,end=None)
    print()
    sys.stdout.flush()

def background():
  while True:
    t = logq.get()
    if not t: break
    logmsg(*t)

## ===
    
def main():
  bt = Thread(target=background)
  bt.start()
  # This is NOT a good socket location for production, it is for 
  # playing around.  I suggest /var/run/milter/myappnamesock for production.
  socketname = os.path.expanduser('~/pythonsock')
  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = myMilter
  flags = Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS
  flags += Milter.ADDRCPT
  flags += Milter.DELRCPT
  Milter.set_flags(flags)       # tell Sendmail which features we use
  print("%s milter startup" % time.strftime('%Y%b%d %H:%M:%S'))
  sys.stdout.flush()
  Milter.runmilter("pythonfilter",socketname,timeout)
  logq.put(None)
  bt.join()
  print("%s bms milter shutdown" % time.strftime('%Y%b%d %H:%M:%S'))

if __name__ == "__main__":
  # You probably do not need a logging process, but if you do, this
  # is one way to do it.
  logq = Queue(maxsize=4)
  main()
