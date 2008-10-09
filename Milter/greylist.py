import time
import shelve
import thread
import logging
import urllib

log = logging.getLogger('milter.greylist')

def quoteAddress(s):
  '''Quote an address so that it's safe to store in the file-system.
  Address can either be a domain name, or local part.
  Returns the quoted address.'''

  s = urllib.quote(s, '@_-+~!.%')
  if s.startswith('.'): s = '%2e' + s[1:]
  return s

class Record(object):
  __slots__ = ( 'firstseen', 'lastseen', 'umis', 'cnt' )

  def __init__(self):
    now = time.time()
    self.firstseen = now
    self.lastseen = now
    self.cnt = 0
    self.umis = None

class Greylist(object):

  def __init__(self,dbname,grey_time=10,grey_expire=4,grey_retain=36):
    self.ignoreLastByte = False
    self.greylist_time = grey_time * 60         # minutes
    self.greylist_expire = grey_expire * 3600   # hours
    self.greylist_retain = grey_retain * 24 * 3600   # days
    self.dbp = shelve.open(dbname,'c',protocol=2)
    self.lock = thread.allocate_lock()
  
  def check(self,ip,sender,recipient):
    "Return number of allowed messages for greylist triple."
    sender = quoteAddress(sender)
    recipient = quoteAddress(recipient)
    key = ip + ':' + sender + ':' + recipient
    self.lock.acquire()
    try:
      dbp = self.dbp
      try:
        r = dbp[key]
        now = time.time()
        if now > r.lastseen + self.greylist_retain:
          # expired
          log.debug('Expired greylist: %s',key)
          r = Record()
        elif now < r.firstseen + self.greylist_time:
          # still greylisted
          log.debug('Early greylist: %s',key)
          #r = Record()
          r.lastseen = now
        elif r.cnt or now < r.firstseen + self.greylist_expire:
          # in greylist window or active
          r.lastseen = now
          r.cnt += 1
          log.debug('Active greylist(%d): %s',r.cnt,key)
        else:
          # passed greylist window
          log.debug('Late greylist: %s',key)
          r = Record()
        dbp[key] = r
      except:
        r = Record()
        dbp[key] = r
      dbp.sync()
    finally:
      self.lock.release()
    return r.cnt
