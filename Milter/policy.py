try:
  from bsddb3 import db
  class DB(object):
    def open(self,fname,mode):
      if mode == 'r': flags = db.DB_RDONLY
      else: raise RuntimeException('unsupported mode')
      self.f = db.DB()
      self.f.open(fname,flags=flags)
    def __contains__(self,key):
      return not not self.f.get(key)
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
    try:
      self.use_colon = conf.access_file_colon
    except:
      self.use_colon = True
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
    if self.use_colon:
      sep = b':'
    else:
      sep = b'!'
    pfx = pfx.encode() + sep
    try:    # try with localpart@domain
      return acf[pfx + self.sender.encode() + sfx].rstrip(b'\x00').decode()
    except KeyError:
      try:  # try with domain
        d = self.domain.encode()
        k = pfx + d + sfx
        while not k in acf and b'.' in d:
          # check partial domains
          d = b'.'.join(d.split(b'.')[1:])
          k = pfx + b'.' + d + sfx
        return acf[k].rstrip(b'\x00').decode()
      except KeyError:
        try:    # try bare prefix
          return acf[pfx + sfx].rstrip(b'\x00').decode()
        except KeyError:
          try:
            return acf[pfx[:-1] + sfx].rstrip(b'\x00').decode()
          except KeyError:
            return None
