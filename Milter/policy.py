try:
  from bsddb3 import db
  class DB(object):
    def open(self,fname,mode):
      if mode == 'r': flags = db.DB_RDONLY
      else: raise RuntimeException('unsupported mode')
      self.f = db.DB()
      self.f.open(fname,flags=flags)
    def __getitem__(self,key):
      v = self.f.get(key)
      if not v: raise KeyError(key)
      return v
    def close(self):
      self.f.close()
  def dbmopen(fname,mode):
    f = DB()
    f.open(fname,mode)
    return f
except ModuleNotFoundError: raise
except:
  import anydbm as dbm
  dbmopen = dbm.open

class MTAPolicy(object):
  "Get SPF policy by result from sendmail style access file."
  def __init__(self,sender,conf,access_file=None):
    if not access_file:
      access_file = conf.access_file
    self.use_nulls = conf.access_file_nulls
    self.sender = sender
    self.domain = sender.split('@')[-1].lower()
    self.acf = None
    self.access_file = access_file

  def close(self):
    if self.acf:
      self.acf.close()

  def __enter__(self): 
    self.acf = None
    if self.access_file:
      try:
        self.acf = dbmopen(self.access_file,'r')
      except:
        print('%s: Cannot open for reading'%self.access_file)
        raise
    return self
  def __exit__(self,t,v,b): self.close()

  def getPolicy(self,pfx):
    acf = self.acf
    if not acf: return None
    if self.use_nulls: sfx = b'\x00'
    else: sfx = b''
    pfx = pfx.encode() + b'!'
    try:
      return acf[pfx + self.sender.encode() + sfx].rstrip(b'\x00').decode()
    except KeyError:
      try:
        return acf[pfx + self.domain.encode() + sfx].rstrip(b'\x00').decode()
      except KeyError:
        try:
          return acf[pfx + sfx].rstrip(b'\x00').decode()
        except KeyError:
          try:
            return acf[pfx[:-1] + sfx].rstrip(b'\x00').decode()
          except KeyError:
            return None
