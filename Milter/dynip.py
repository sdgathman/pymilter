# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# Heuristically determine whether a domain name is for a dynamic IP.

# examples we don't yet recognize:
#
# wiley-268-8196.roadrunner.nf.net at ('205.251.174.46', 4810)
# cbl-sd-02-79.aster.com.do at ('200.88.62.79', 4153)

import re

ip3 = re.compile('[0-9]{1,3}')
hpats = (
 'h[0-9a-f]{12}[.]',
 'h\d*n\d*c\d*o\d*\.',
 'pcp\d{6,10}pcs[.]',
 'no-reverse',
 'S[0-9a-f]{16}[.][a-z]{2}[.]',
 'user<3>\.',
 '[Cc]ust<3>\.',
 '^<3>\.',
 'ppp[^.]*<3>\.',
 '-ppp\d*\.',
 '\d*-<3>\.',
 '[0-9a-f]{1,3}-<3>\.',
 'p<3>\.pool',
 'h<3>\.',
 'xdsl-\d*\.',
 '-\d*-\d*\.',
 '\.adsl\.',
 '\.cable\.'
)
rehmac = re.compile('|'.join(hpats))

def is_dynip(host,addr):
  """Return True if hostname is for a dynamic ip.
  Examples:

  >>> is_dynip('post3.fabulousdealz.com','69.60.99.112')
  False
  >>> is_dynip('adsl-69-208-201-177.dsl.emhril.ameritech.net','69.208.201.177')
  True
  >>> is_dynip('[1.2.3.4]','1.2.3.4')
  True
  >>> is_dynip('c-71-63-151-151.hsd1.mn.comcast.net','71.63.151.151')
  True
  """
  if host.startswith('[') and host.endswith(']'):
    return True
  if addr:
    if host.find(addr) >= 0: return True
    a = addr.split('.')
    ia = map(int,a)
    h = host
    m = ip3.findall(host)
    if m:
      g = map(int,m)[:4]
      ia3 = (ia[1:],ia[:3])
      if g[-3:] in ia3: return True
      if g[0] == ia[3] and g[1:3] == ia[:2]: return True
      if g[-2:] == ia[2:]: return True
      g.reverse()
      if g[:3] in ia3: return True
      if g[:2] == ia[2:]: return True
      if ia[2:] in (g[:2],g[-2:]): return True
      for m in ip3.finditer(host):
        if int(m.group()) == ia[3]:
	  h = host[:m.start()] + '<3>' + host[m.end():]
	  break
    if rehmac.search(h): return True
    if host.find(''.join(a[:3])) >= 0: return True
    if host.find(''.join(a[1:])) >= 0: return True
    x = "%02x%02x%02x%02x" % tuple(ia)
    if host.lower().find(x) >= 0: return True
  return False

if __name__ == '__main__':
  import fileinput
  import sets
  seen = sets.Set()
  for ln in fileinput.input():
    a = ln.split()
    if a[3:5] == ['connect','from']:
      host = a[5]
      if host.startswith('[') and host.endswith(']'):
	continue	# no PTR
      ip = a[7][2:-2]
      if ip in seen: continue
      seen.add(ip)
      if is_dynip(host,ip):
        print '%s\t%s DYN' % (ip,host)
      else:
        print '%s\t%s' % (ip,host)
