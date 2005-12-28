# Analyze milter log to find abusers

class Connection(object);
  def __init__(self,dt,tm,id,ip)
    self.dt = dt
    self.tm = tm
    self.id = id
    _,self.host,self.ip = ip.split(None,2)

def connections(fp):
  conndict = {}
  for line in fp:
    a = line.split(None,4)
    if len(a) < 4: continue
    dt,tm,id,op = a[:4]
    if id,op == 'bms','milter':
      # FIXME: optionally yield all partial connections
      conndict = {}
    key = id
    if op == 'connect':
      ip = a[4].rstrip()
      conn = Connection(dt,tm,id,ip)
      conndict[key] = conn
    else:
      conn = conndict[key]
      if op == 'Subject:':
        if len(a) > 4: conn.subject = a[4].rstrip()
      elif op == 'mail':
        _,conn.mfrom = a[4].split(None,2)
      elif op == 'rcpt':
        _,conn.rcpt = a[4].split(None,2)
      elif op in ('eom','dspam','abort'):
        del conndict[key]
	conn.enddt = dt
	conn.endtm = tm
	conn.result = op
	yield conn
      elif op in ('REJECT:','DSPAM:','SPAM:'):
	conn.enddt = dt
	conn.endtm = tm
        conn.result = op
	conn.resmsg = a[4].rstrip()
	yield conn
      else:
	print line.rstrip()


if __name__ == '__main__':
  import gzip
  import sys
  for fn in sys.argv[:1]:
    if fn.endswith('.gz'):
      fp = gzip.open(fn)
    else:
      fp = open(fn)
    for conn in connections(fp):
      print conn.dt,conn.tm,conn.id,conn.subject,conn.mfrom,conn.rcpt
