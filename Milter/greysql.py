import time
import logging
import urllib
import sqlite3
import thread
from datetime import datetime

log = logging.getLogger('milter.greylist')

_db_lock = thread.allocate_lock()

class Greylist(object):

  def __init__(self,dbname,grey_time=10,grey_expire=4,grey_retain=36):
    self.ignoreLastByte = False
    self.greylist_time = grey_time * 60         # minutes
    self.greylist_expire = grey_expire * 3600   # hours
    self.greylist_retain = grey_retain * 24 * 3600   # days
    self.conn = sqlite3.connect(dbname)
    self.conn.row_factory = sqlite3.Row
    try:
      self.conn.execute('''create table greylist(
        ip text , sender text, recipient text,
        firstseen timestamp, lastseen timestamp, cnt integer, umis text,
        primary key (ip,sender,recipient))''')
    except: pass

  def import_csv(self,fp):
    import csv
    rdr = csv.reader(fp)
    cur = self.conn.execute('begin immediate')
    try:
      for r in rdr:
        cur.execute('''insert into 
          greylist(ip,sender,recipient,firstseen,lastseen,cnt,umis)
          values(?,?,?,?,?,?,?)''', r)
      self.conn.commit()
    finally:
      cur.close();

  def clean(self,timeinc=0):
    "Delete records past the retention limit."
    now = time.time() + timeinc - self.greylist_retain
    cur = self.conn.cursor()
    try:
      cur.execute('delete from greylist where lastseen < ?',(now,))
      cnt = cur.rowcount
      self.conn.commit()
    finally: cur.close()
    return cnt

  def check(self,ip,sender,recipient,timeinc=0):
    "Return number of allowed messages for greylist triple."
    _db_lock.acquire()
    cur = self.conn.execute('begin immediate')
    try:
      cur.execute('''select firstseen,lastseen,cnt,umis from greylist where
        ip=? and sender=? and recipient=?''',(ip,sender,recipient))
      r = cur.fetchone()
      now = time.time() + timeinc
      cnt = 0
      if not r:
        cur.execute('''insert into 
          greylist(ip,sender,recipient,firstseen,lastseen,cnt,umis)
          values(?,?,?,?,?,?,?)''', (ip,sender,recipient,now,now,0,None))
      elif now > r['lastseen'] + self.greylist_retain:
        # expired
        log.debug('Expired greylist: %s:%s:%s',ip,sender,recipient)
        cur.execute('''update greylist set firstseen=?,lastseen=?,cnt=?,umis=?
          where ip=? and sender=? and recipient=?''',
          (now,now,0,None,ip,sender,recipient))
      elif now < r['firstseen'] + self.greylist_time + 5:
        # still greylisted
        log.debug('Early greylist: %s:%s:%s',ip,sender,recipient)
        #r = Record()
        cur.execute('''update greylist set lastseen=?
          where ip=? and sender=? and recipient=?''',
          (now,ip,sender,recipient))
      elif r['cnt'] or now < r['firstseen'] + self.greylist_expire:
        # in greylist window or active
        cnt = r['cnt'] + 1
        cur.execute('''update greylist set lastseen=?,cnt=?
          where ip=? and sender=? and recipient=?''',
          (now,cnt,ip,sender,recipient))
        log.debug('Active greylist(%d): %s:%s:%s',cnt,ip,sender,recipient)
      else:
        # passed greylist window
        log.debug('Late greylist: %s:%s:%s',ip,sender,recipient)
        cur.execute('''update greylist set firstseen=?,lastseen=?,cnt=?,umis=?
          where ip=? and sender=? and recipient=?''',
          (now,now,0,None,ip,sender,recipient))
      self.conn.commit()
    finally:
      cur.close()
      _db_lock.release()
    return cnt

  def close(self):
    self.conn.close()

if __name__ == '__main__':
  import sys
  g = Greylist(sys.argv[1])
  try:
    g.import_csv(sys.stdin)
  finally: g.close()
