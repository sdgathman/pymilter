## @package Milter.dns
# Provide a higher level interface to pydns.

import DNS
from DNS import DNSError

MAX_CNAME = 10

## Lookup DNS records by label and RR type.
# The response can include records of other types that the DNS
# server thinks we might need.
# @param name the DNS label to lookup
# @param qtype the name of the DNS RR type to lookup
# @return a list of ((name,type),data) tuples
def DNSLookup(name, qtype):
    try:
	# To be thread safe, we create a fresh DnsRequest with
	# each call.  It would be more efficient to reuse
	# a req object stored in a Session.
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

  ## Additional DNS RRs we can safely cache.
  # We have to be careful which additional DNS RRs we cache.  For
  # instance, PTR records are controlled by the connecting IP, and they
  # could poison our local cache with bogus A and MX records.  
  # Each entry is a tuple of (query_type,rr_type).  So for instance,
  # the entry ('MX','A') says it is safe (for milter purposes) to cache
  # any 'A' RRs found in an 'MX' query.
  SAFE2CACHE = frozenset((
    ('MX','MX'), ('MX','A'),
    ('CNAME','CNAME'), ('CNAME','A'),
    ('A','A'),
    ('AAAA','AAAA'),
    ('PTR','PTR'),
    ('NS','NS'), ('NS','A'),
    ('TXT','TXT'),
    ('SPF','SPF')
  ))

  ## Cached DNS lookup.
  # @param name the DNS label to query
  # @param qtype the query type, e.g. 'A'
  # @param cnames tracks CNAMES already followed in recursive calls
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
