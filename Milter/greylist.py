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

  def __init__(self,timeinc=0):
    now = time.time() + timeinc
    self.firstseen = now
    self.lastseen = now
    self.cnt = 0
    self.umis = None

  def __str__(self):
    return "Grey[%s:%s:%s:%d]" % (
        time.ctime(self.firstseen),time.ctime(self.lastseen),
        self.umis,self.cnt
    )

class Greylist(object):

  def __init__(self,dbname,grey_time=10,grey_expire=4,grey_retain=36):
    self.ignoreLastByte = False
    self.greylist_time = grey_time * 60         # minutes
    self.greylist_expire = grey_expire * 3600   # hours
    self.greylist_retain = grey_retain * 24 * 3600   # days
    self.dbp = shelve.open(dbname,'c',protocol=2)
    self.lock = thread.allocate_lock()

  def export_csv(self,fp,timeinc=0):
    "Export records to csv."
    import csv
    dbp = self.dbp
    w = csv.writer(fp)
    now = time.time() + timeinc
    for key, r in dbp.iteritems():
      if now > r.lastseen + self.greylist_retain: continue
      ip,sender,recipient = key.rsplit(':',2)
      w.writerow([ip,sender,recipient,r.firstseen,r.lastseen,r.cnt,r.umis])

  def clean(self,timeinc=0):
    "Delete records past the retention limit."
    now = time.time() + timeinc
    cnt = 0
    dbp = self.dbp
    for key, r in dbp.iteritems():
      #print key,r,time.ctime(now)
      if now > r.lastseen + self.greylist_retain:
        self.lock.acquire()
        try:
          r = dbp[key]
          now = time.time() + timeinc
          if now > r.lastseen + self.greylist_retain:
            del dbp[key]
            cnt += 1
        finally:
          self.lock.release()
    return cnt
  
  def check(self,ip,sender,recipient,timeinc=0):
    "Return number of allowed messages for greylist triple."
    sender = quoteAddress(sender)
    recipient = quoteAddress(recipient)
    key = ip + ':' + sender + ':' + recipient
    self.lock.acquire()
    try:
      dbp = self.dbp
      try:
        r = dbp[key]
        now = time.time() + timeinc
        if now > r.lastseen + self.greylist_retain:
          # expired
          log.debug('Expired greylist: %s',key)
          r = Record(timeinc)
        elif now < r.firstseen + self.greylist_time + 5:
          # still greylisted
          log.debug('Early greylist: %s',key)
          #r = Record(timeinc)
          r.lastseen = now
        elif r.cnt or now < r.firstseen + self.greylist_expire:
          # in greylist window or active
          r.lastseen = now
          r.cnt += 1
          log.debug('Active greylist(%d): %s',r.cnt,key)
        else:
          # passed greylist window
          log.debug('Late greylist: %s',key)
          r = Record(timeinc)
        dbp[key] = r
      except:
        r = Record(timeinc)
        dbp[key] = r
      dbp.sync()
    finally:
      self.lock.release()
    return r.cnt

  def close(self):
    self.dbp.close()

if __name__ == '__main__':
  import sys
  g = Greylist(sys.argv[1],5,24,36)
  try:
    g.export_csv(sys.stdout)
  finally: g.close()
