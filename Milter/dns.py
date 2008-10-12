# provide a higher level interface to pydns

import DNS
from DNS import DNSError

MAX_CNAME = 10

def DNSLookup(name, qtype):
    try:
        req = DNS.DnsRequest(name, qtype=qtype)
        resp = req.req()
        #resp.show()
        # key k: ('wayforward.net', 'A'), value v
        # FIXME: pydns returns AAAA RR as 16 byte binary string, but
        # A RR as dotted quad.  For consistency, this driver should
        # return both as binary string.
        return [((a['name'], a['typename']), a['data']) for a in resp.answers]
    except IOError, x:
        raise DNSError, str(x)

class Session(object):
  """A Session object has a simple cache with no TTL that is valid
   for a single "session", for example an SMTP conversation."""
  def __init__(self):
    self.cache = {}

  # We have to be careful which additional DNS RRs we cache.  For
  # instance, PTR records are controlled by the connecting IP, and they
  # could poison our local cache with bogus A and MX records.  

  SAFE2CACHE = {
    ('MX','A'): None,
    ('MX','MX'): None,
    ('CNAME','A'): None,
    ('CNAME','CNAME'): None,
    ('A','A'): None,
    ('AAAA','AAAA'): None,
    ('PTR','PTR'): None,
    ('NS','NS'): None,
    ('NS','A'): None,
    ('TXT','TXT'): None,
    ('SPF','SPF'): None
  }


  def dns(self, name, qtype, cnames=None):
    """DNS query.

    If the result is in cache, return that.  Otherwise pull the
    result from DNS, and cache ALL answers, so additional info
    is available for further queries later.

    CNAMEs are followed.

    If there is no data, [] is returned.

    pre: qtype in ['A', 'AAAA', 'MX', 'PTR', 'TXT', 'SPF']
    post: isinstance(__return__, types.ListType)
    """
    result = self.cache.get( (name, qtype) )
    cname = None

    if not result:
        safe2cache = Session.SAFE2CACHE
        for k, v in DNSLookup(name, qtype):
            if k == (name, 'CNAME'):
                cname = v
            if (qtype,k[1]) in safe2cache:
                self.cache.setdefault(k, []).append(v)
        result = self.cache.get( (name, qtype), [])
    if not result and cname:
        if not cnames:
            cnames = {}
        elif len(cnames) >= MAX_CNAME:
            #return result    # if too many == NX_DOMAIN
            raise DNSError('Length of CNAME chain exceeds %d' % MAX_CNAME)
        cnames[name] = cname
        if cname in cnames:
            raise DNSError, 'CNAME loop'
        result = self.dns(cname, qtype, cnames=cnames)
    return result

DNS.DiscoverNameServers()

if __name__ == '__main__':
  import sys
  s = Session()
  for n,t in zip(*[iter(sys.argv[1:])]*2):
    print n,t
    print s.dns(n,t)
