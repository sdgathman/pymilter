# Analyze milter log to find abusers
import traceback
import sys

def parse_addr(a):
  beg = a.find('<')
  end = a.find('>')
  if beg >= 0:
    if end > beg: return a[beg+1:end]
  return a

class Connection(object):
  def __init__(self,dt,tm,id,ip=None,conn=None):
    self.dt = dt
    self.tm = tm
    self.id = id
    if ip:
      _,self.host,self.ip = ip.split(None,2)
    elif conn:
      self.ip = conn.ip
      self.host = conn.host
      self.helo = conn.helo
    self.subject = None
    self.rcpt = []
    self.mfrom = None
    self.helo = None
    self.innoc = []
    self.whitelist = False

def connections(fp):
  conndict = {}
  termdict = {}
  for line in fp:
    if line.startswith('{'): continue
    a = line.split(None,4)
    if len(a) < 4: continue
    dt,tm,id,op = a[:4]
    if (id,op) == ('bms','milter'):
      # FIXME: optionally yield all partial connections in conndict
      conndict = {}
      termdict = {}
      continue
    if id[0] == '[' and id[-1] == ']':
      try:
	key = int(id[1:-1])
      except:
        print >>sys.stderr,'bad id:',line.rstrip()
	continue
    else: continue
    if op == 'connect':
      ip = a[4].rstrip()
      conn = Connection(dt,tm,id,ip=ip)
      conndict[key] = conn
    elif op in (
	'DISCARD:','TAG:','CBV:','Large','No',
	'NOTE:','From:','Sender:','TRAIN:'):
      continue
    else:
      op = op.lower()
      try:
	conn = conndict[key]
      except KeyError:
        try:
	  conn = termdict[key]
	  del termdict[key]
	  conndict[key] = conn
	except KeyError:
	  print >>sys.stderr,'key error:',line.rstrip()
	  continue
      try:
	if op == 'subject:':
	  if len(a) > 4:
	    conn.subject = a[4].rstrip()
	elif op == 'innoc:':
	  conn.innoc.append(a[4].rstrip())
	elif op == 'whitelist':
	  conn.whitelist = True
	elif op == 'x-mailer:':
	  if len(a) > 4:
	    conn.mailer = a[4].rstrip()
        elif op == 'x-guessed-spf:':
          conn.spfguess = a[4]
	elif op == 'received-spf:':
	  conn.spfres,conn.spfmsg = a[4].rstrip().split(None,1)
	elif op == 'received:':
	  conn.received = a[4].rstrip()
	elif op == 'temp':
	  _,conn.tempfile = a[4].rstrip().split(None,1)
	elif op == 'srs':
	  _,conn.srsrcpt = a[4].rstrip().split(None,1)
	elif op == 'mail':
	  _,conn.mfrom = a[4].rstrip().split(None,1)
	elif op == 'rcpt':
	  _,rcpt = a[4].rstrip().split(None,1)
	  conn.rcpt.append(rcpt)
	elif op == 'hello':
	  _,conn.helo = a[4].rstrip().split(None,1)
	elif op in ('eom','dspam','abort'):
	  del conndict[key]
	  conn.enddt = dt
	  conn.endtm = tm
	  conn.result = op
	  yield conn
	  termdict[key] = Connection(conn.dt,conn.tm,conn.id,conn=conn)
	elif op in ('reject:','dspam:','tempfail:','reject','fail:','honeypot:'):
	  del conndict[key]
	  conn.enddt = dt
	  conn.endtm = tm
	  conn.result = op
	  conn.resmsg = a[4].rstrip()
	  yield conn
	  termdict[key] = Connection(conn.dt,conn.tm,conn.id,conn=conn)
	elif op in ('fp:','spam:'):
	  del conndict[key]
	  termdict[key] = Connection(conn.dt,conn.tm,conn.id,conn=conn)
	else:
	  print >>sys.stderr,'unknown op:',line.rstrip()
      except Exception:
	print >>sys.stderr,'error:',line.rstrip()
        traceback.print_exc()

if __name__ == '__main__':
  import gzip
  for fn in sys.argv[1:]:
    if fn.endswith('.gz'):
      fp = gzip.open(fn)
    else:
      fp = open(fn)
    for conn in connections(fp):
      if conn.rcpt and conn.mfrom:
        for r in conn.rcpt:
	  if r.lower().find('iancarter') > 0: break
	else:
	  if conn.mfrom.lower().find('iancarter') < 0: continue
	print >>sys.stderr,conn.result,conn.dt,conn.tm,conn.id,conn.subject,parse_addr(conn.mfrom),
	for a in conn.rcpt:
	  print parse_addr(a),
	print
