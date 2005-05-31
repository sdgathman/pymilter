# Analyze milter log to find abusers

fp = open('/var/log/milter/milter.log','r')
subdict = {}
ipdict = {}
spamcnt = {}
for line in fp:
  a = line.split(None,4)
  if len(a) < 4: continue
  dt,tm,id,op = a[:4]
  if op == 'Subject:':
    if len(a) > 4: subdict[id] = a[4].rstrip()
  elif op == 'connect':
    ipdict[id] = a[4].rstrip()
  elif op in ('eom','dspam'):
    if id in subdict: del subdict[id]
    if id in ipdict: del ipdict[id]
  elif op in ('REJECT:','DSPAM:','SPAM:','abort'):
    if id in subdict:
      if id in ipdict:
        ip = ipdict[id]
	del ipdict[id]
	f,host,raw = ip.split(None,2)
	if host in spamcnt:
	  spamcnt[host] += 1
	else:
	  spamcnt[host] = 1
      else: ip = ''
      print dt,tm,op,a[4].rstrip(),subdict[id]
      del subdict[id]
    else:
      print line.rstrip()
print len(subdict),'leftover entries'

spamlist = filter(lambda x: x[1] > 1,spamcnt.items())
spamlist.sort(lambda x,y: x[1] - y[1])
for ip,cnt in spamlist:
  print cnt,ip
