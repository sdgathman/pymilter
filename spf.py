#!/usr/bin/env python
"""SPF (Sender-Permitted From) implementation.

Copyright (c) 2003, Terence Way
This module is free software, and you may redistribute it and/or modify
it under the same terms as Python itself, so long as this copyright message
and disclaimer are retained in their original form.

IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
THIS CODE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE.  THE CODE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
AND THERE IS NO OBLIGATION WHATSOEVER TO PROVIDE MAINTENANCE,
SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

For more information about SPF, a tool against email forgery, see
	http://spf.pobox.com

For news, bugfixes, etc. visit the home page for this implementation at
	http://www.wayforward.net/spf/
"""

# Changes:
#    9-dec-2003, v1.1, Meng Weng Wong added PTR code, THANK YOU
#   11-dec-2003, v1.2, ttw added macro expansion, exp=, and redirect=
#   13-dec-2003, v1.3, ttw added %{o} original domain macro,
#                      print spf result on command line, support default=,
#                      support localhost, follow DNS CNAMEs, cache DNS results
#                      during query, support Python 2.2 for Mac OS X
#   16-dec-2003, v1.4, ttw fixed include handling (include is a mechanism,
#                      complete with status results, so -include: should work.
#                      Expand macros AFTER looking for status characters ?-+
#                      so altavista.com SPF records work.
#   17-dec-2003, v1.5, ttw use socket.inet_aton() instead of DNS.addr2bin, so
#                      n, n.n, and n.n.n forms for IPv4 addresses work, and to
#                      ditch the annoying Python 2.4 FutureWarning
#   18-dec-2003, v1.6, Failures on Intel hardware: endianness.  Use ! on
#                      struct.pack(), struct.unpack().
# $Log$
# Revision 1.5  2004/04/05 22:29:46  stuart
# SPF best_guess,
#
# Revision 1.4  2004/03/25 03:27:34  stuart
# Support delegation of SPF records.
#
# Revision 1.3  2004/03/13 12:23:23  stuart
# Expanded result codes.  Tolerate common method misspellings.
#

__author__ = "Terence Way"
__email__ = "terry@wayforward.net"
__version__ = "1.6: December 18, 2003"
MODULE = 'spf'

USAGE = """To check an incoming mail request:
    % python spf.py {ip} {sender} {helo}
    % python spf.py 69.55.226.139 tway@optsw.com mx1.wayforward.net

To test an SPF record:
    % python spf.py "v=spf1..." {ip} {sender} {helo}
    % python spf.py "v=spf1 +mx +ip4:10.0.0.1 -all" 10.0.0.1 tway@foo.com a    

To fetch an SPF record:
    % python spf.py {domain}
    % python spf.py wayforward.net

To test this script (and to output this usage message):
    % python spf.py
"""

import re
import socket  # for inet_ntoa() and inet_aton()
import struct  # for pack() and unpack()
import time    # for time()

import DNS	# http://pydns.sourceforge.net

# 32-bit IPv4 address mask
MASK = 0xFFFFFFFFL

# Regular expression to look for modifiers
RE_MODIFIER = re.compile(r'^([a-zA-Z]+)=')

# Regular expression to find macro expansions
RE_CHAR = re.compile(r'%(%|_|-|(\{[a-zA-Z][0-9]*r?[^\}]*\}))')

# Regular expression to break up a macro expansion
RE_ARGS = re.compile(r'([0-9]*)(r?)([^0-9a-zA-Z]*)')

# Local parts and senders have their delimiters replaced with '.' during
# macro expansion
#
JOINERS = {'l': '.', 's': '.'}

RESULTS = {'+': 'pass', '-': 'fail', '?': 'neutral', '~': 'softfail',
           'pass': 'pass', 'fail': 'fail', 'unknown': 'unknown',
	   'neutral': 'neutral', 'softfail': 'softfail',
	   'none': 'none' }

EXPLANATIONS = {'pass': 'sender SPF verified', 'fail': 'access denied',
                'unknown': 'SPF unknown', 'softfail': 'domain in transition',
		'neutral': 'access neither permitted nor denied',
		'none': 'no SPF records'
		}

# if set to a domain name, search _spf.domain namespace if no SPF record
# found in source domain.

DELEGATE = None

# support pre 2.2.1....
try:
	bool, True, False = bool, True, False
except NameError:
	False, True = 0, 1
	def bool(x): return not not x
# ...pre 2.2.1

# standard default SPF record
DEFAULT_SPF = 'v=spf1 a/24 mx/24 ptr'

def check(i, s, h,default=None):
	"""Test an incoming MAIL FROM:<s>, from a client with ip address i.
	h is the HELO/EHLO domain name.

	Returns (result, mta-status-code, explanation) where result in
	['pass', 'unknown', 'fail', 'error', 'softfail', 'none', 'neutral' ].

	Example:
	>>> check(i='127.0.0.1', s='terry@wayforward.net', h='localhost')
	('pass', 250, 'local connections always pass')

	#>>> check(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

	"""
	if i.startswith('127.'):
		return ('pass', 250, 'local connections always pass')

	try:
		q = query(i=i, s=s, h=h)
		spf = q.dns_spf(q.d)
		if not spf and default:
		  spf = default
		return q.check(spf)
	except DNS.DNSError:
		return ('error', 450, 'SPF DNS Error')

def best_guess(i, s, h,spf=DEFAULT_SPF):
	q = query(i=i, s=s, h=h)
	return q.check(spf)

class query(object):
	"""A query object keeps the relevant information about a single SPF
	query:

	i: ip address of SMTP client
	s: sender declared in MAIL FROM:<>
	l: local part of sender s
	d: current domain, initially domain part of sender s
	h: EHLO/HELO domain
	v: 'in-addr' for IPv4 clients and 'ip6' for IPv6 clients
	t: current timestamp
	p: SMTP client domain name
	o: domain part of sender s

	This is also, by design, the same variables used in SPF macro
	expansion.

	Also keeps cache: DNS cache.
	"""
	def __init__(self, i, s, h):
		self.i, self.s, self.h = i, s, h
		self.l, self.o = split_email(s, h)
		self.t = str(int(time.time()))
		self.v = 'in-addr'
		self.d = self.o
		self.p = None
		self.cache = {}

	def getp(self):
		if not self.p:
			p = self.dns_ptr(self.i)
			if len(p) > 0:
				self.p = p[0]
			else:
				self.p = self.i
		return self.p

	def check(self, spf):
		"""
		Returns (result, mta-status-code, explanation) where
		result in ['fail', 'unknown', 'pass']
		"""
		return self.check1(spf, self.d, 0)

	def check1(self, spf, domain, recursion):
		# spf rfc: 3.7 Processing Limits
		#
		if recursion > 10:
			return ('unknown', 250, 'SPF recursion limit exceeded')
		try:
			tmp, self.d = self.d, domain
			return self.check0(spf, recursion)
		finally:
			self.d = tmp

	def check0(self, spf, recursion):
		"""Test this query information against SPF text.

		Returns (result, mta-status-code, explanation) where
		result in ['fail', 'unknown', 'pass', 'none']
		"""

		if not spf:
			return ('none', 250, 'no SPF records')

		# split string by whitespace, drop the 'v=spf1'
		#
		spf = spf.split()[1:]

		# copy of explanations to be modified by exp=
		exps = dict(EXPLANATIONS)
		redirect = None

		# no mechanisms at all cause unknown result, unless
		# overridden with 'default=' modifier
		#
		default = 'neutral'

		# Look for modifiers
		#
		for m in spf:
			m = RE_MODIFIER.split(m)[1:]
			if len(m) != 2: continue

			if m[0] == 'exp':
				exps['fail'] = exps['unknown'] = \
					self.get_explanation(m[1])
			elif m[0] == 'redirect':
				redirect = self.expand(m[1])
			elif m[0] == 'default':
				# default=- is the same as default=fail
				default = RESULTS.get(m[1], default)

			# spf rfc: 3.6 Unrecognized Mechanisms and Modifiers

		# Look for mechanisms
		#
		for mech in spf:
			if RE_MODIFIER.match(mech): continue
			m, arg, cidrlength = parse_mechanism(mech, self.d)

			# map '?' '+' or '-' to 'unknown' 'pass' or 'fail'
			result = RESULTS.get(m[0])
			if result:
				# eat '?' '+' or '-'
				m = m[1:]
			else:
				# default pass
				result = 'pass'

			if m in ['a', 'mx', 'ptr', 'exists', 'include']:
				arg = self.expand(arg)

			if m == 'include':
				if arg != self.d:
					tmp = self.check1(self.dns_spf(arg),
					                  arg, recursion + 1)
					if tmp[0] == 'pass':
						break
					if tmp[0] != 'fail':
						return tmp

			elif m == 'all':
				break

			elif m == 'exists':
				if len(self.dns_a(arg)) > 0:
					break

			elif m == 'a':
				if cidrmatch(self.i, self.dns_a(arg),
				             cidrlength):
					break

			elif m == 'mx':
				if cidrmatch(self.i, self.dns_mx(arg),
				             cidrlength):
					break

			elif m in ('ip4', 'ipv4') and arg != self.d:
				if cidrmatch(self.i, [arg], cidrlength):
					break

			elif m in ('ptr', 'prt'):
				if domainmatch(self.validated_ptrs(self.i),
				               arg):
					break

			else:
				# unknown mechanisms cause immediate unknown
				# abort results
				return ('unknown', 250, mech)

		else:
			# no matches
			if redirect:
				return self.check1(self.dns_spf(redirect),
				                   redirect, recursion+1)
			else:
				result = default

		if result == 'fail':
			return (result, 550, exps[result])
		else:
			return (result, 250, exps[result])

	def get_explanation(self, spec):
		"""Expand an explanation."""
		return self.expand(''.join(self.dns_txt(self.expand(spec))))

	def expand(self, str):
		"""Do SPF RFC macro expansion.

		Examples:
		>>> q = query(s='strong-bad@email.example.com',
		...           h='mx.example.org', i='192.0.2.3')
		>>> q.p = 'mx.example.org'

		>>> q.expand('%{d}')
		'email.example.com'

		>>> q.expand('%{d4}')
		'email.example.com'

		>>> q.expand('%{d3}')
		'email.example.com'

		>>> q.expand('%{d2}')
		'example.com'

		>>> q.expand('%{d1}')
		'com'

		>>> q.expand('%{p}')
		'mx.example.org'

		>>> q.expand('%{p2}')
		'example.org'

		>>> q.expand('%{dr}')
		'com.example.email'
	
		>>> q.expand('%{d2r}')
		'example.email'

		>>> q.expand('%{l}')
		'strong-bad'

		>>> q.expand('%{l-}')
		'strong.bad'

		>>> q.expand('%{lr}')
		'strong-bad'

		>>> q.expand('%{lr-}')
		'bad.strong'

		>>> q.expand('%{l1r-}')
		'strong'

		>>> q.expand('%{ir}.%{v}._spf.%{d2}')
		'3.2.0.192.in-addr._spf.example.com'

		>>> q.expand('%{lr-}.lp._spf.%{d2}')
		'bad.strong.lp._spf.example.com'

		>>> q.expand('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}')
		'bad.strong.lp.3.2.0.192.in-addr._spf.example.com'

		>>> q.expand('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}')
		'3.2.0.192.in-addr.strong.lp._spf.example.com'

		>>> q.expand('%{p2}.trusted-domains.example.net')
		'example.org.trusted-domains.example.net'

		>>> q.expand('%{p2}.trusted-domains.example.net')
		'example.org.trusted-domains.example.net'

		"""
		end = 0
		result = ''
		for i in RE_CHAR.finditer(str):
			result += str[end:i.start()]
			macro = str[i.start():i.end()]
			if macro == '%%':
				result += '%'
			elif macro == '%_':
				result += ' '
			elif macro == '%-':
				result += '%20'
			else:
				letter = macro[2].lower()
				if letter == 'p':
					self.getp()
				expansion = getattr(self, letter, '')
				if expansion:
					result += expand_one(expansion,
						macro[3:-1],
					        JOINERS.get(letter))

			end = i.end()
		return result + str[end:]

	def dns_spf(self, domain):
		"""Get the SPF record recorded in DNS for a specific domain
		name.  Returns None if not found, or if more than one record
		is found.
		"""
		a = [t for t in self.dns_txt(domain) if t.startswith('v=spf1')]
		if not a and DELEGATE:
		  a = [t
		    for t in self.dns_txt(domain+'._spf.'+DELEGATE)
		      if t.startswith('v=spf1')
		  ]
		if len(a) == 1:
			return a[0]
		else:
			return None

	def dns_txt(self, domainname):
		return [t for a in self.dns(domainname, 'TXT') for t in a]

	def dns_mx(self, domainname):
		"""Get a list of IP addresses for all MX exchanges for a
		domain name.
		"""
		return [a for mx in self.dns(domainname, 'MX') \
		          for a in self.dns_a(mx[1])]

	def dns_a(self, domainname):
		"""Get a list of IP addresses for a domainname."""
		return self.dns(domainname, 'A')

	def dns_aaaa(self, domainname):
		"""Get a list of IPv6 addresses for a domainname."""
		return self.dns(domainname, 'AAAA')

	def validated_ptrs(self, i):
		"""Figure out the validated PTR domain names for a given IP
		address.
		"""
		return [p for p in self.dns_ptr(i) if i in self.dns_a(p)]

	def dns_ptr(self, i):
		"""Get a list of domain names for an IP address."""
		return self.dns(reverse_dots(i) + ".in-addr.arpa", 'PTR')

	def dns(self, name, qtype):
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
			req = DNS.DnsRequest(name, qtype=qtype)
			resp = req.req()
			for a in resp.answers:
				# key k: ('wayforward.net', 'A'), value v
				k, v = (a['name'], a['typename']), a['data']
				if k == (name, 'CNAME'):
					cname = v
				self.cache.setdefault(k, []).append(v)
			result = self.cache.get( (name, qtype), [])
		if not result and cname:
			result = self.dns(cname, qtype)
		return result

def split_email(s, h):
	"""Given a sender email s and a HELO domain h, create a valid tuple
	(l, d) local-part and domain-part.

	Examples:
	>>> split_email('', 'wayforward.net')
	('postmaster', 'wayforward.net')

	>>> split_email('foo.com', 'wayforward.net')
	('postmaster', 'foo.com')

	>>> split_email('terry@wayforward.net', 'optsw.com')
	('terry', 'wayforward.net')
	"""
	if not s:
		return 'postmaster', h
	else:
		parts = s.split('@', 1)
		if len(parts) == 2:
			return tuple(parts)
		else:
			return 'postmaster', s

def parse_mechanism(str, d):
	"""Breaks A, MX, IP4, and PTR mechanisms into a (name, domain,
	cidr) tuple.  The domain portion defaults to d if not present,
	the cidr defaults to 32 if not present.

	Examples:
	>>> parse_mechanism('a', 'foo.com')
	('a', 'foo.com', 32)

	>>> parse_mechanism('a:bar.com', 'foo.com')
	('a', 'bar.com', 32)

	>>> parse_mechanism('a/24', 'foo.com')
	('a', 'foo.com', 24)

	>>> parse_mechanism('a:bar.com/16', 'foo.com')
	('a', 'bar.com', 16)
	"""
	a = str.split('/')
	if len(a) == 2:
		a, port = a[0], int(a[1])
	else:
		a, port = str, 32

	b = a.split(':')
	if len(b) == 2:
		return b[0], b[1], port
	else:
		return a, d, port

def reverse_dots(name):
	"""Reverse dotted IP addresses or domain names.

	Example:
	>>> reverse_dots('192.168.0.145')
	'145.0.168.192'

	>>> reverse_dots('email.example.com')
	'com.example.email'
	"""
	a = name.split('.')
	a.reverse()
	return '.'.join(a)

def domainmatch(ptrs, domainsuffix):
	"""grep for a given domain suffix against a list of validated PTR
	domain names.

	Examples:
	>>> domainmatch(['FOO.COM'], 'foo.com')
	1

	>>> domainmatch(['moo.foo.com'], 'FOO.COM')
	1

	>>> domainmatch(['moo.bar.com'], 'foo.com')
	0

	"""
	domainsuffix = domainsuffix.lower()
	for ptr in ptrs:
		ptr = ptr.lower()

		if ptr == domainsuffix or ptr.endswith('.' + domainsuffix):
			return True

	return False

def cidrmatch(i, ipaddrs, cidr_length = 32):
	"""Match an IP address against a list of other IP addresses.

	Examples:
	>>> cidrmatch('192.168.0.45', ['192.168.0.44', '192.168.0.45'])
	1

	>>> cidrmatch('192.168.0.43', ['192.168.0.44', '192.168.0.45'])
	0

	>>> cidrmatch('192.168.0.43', ['192.168.0.44', '192.168.0.45'], 24)
	1
	"""
	c = cidr(i, cidr_length)
	for ip in ipaddrs:
		if cidr(ip, cidr_length) == c:
			return True
	return False

def cidr(i, n):
	"""Convert an IP address string with a CIDR mask into a 32-bit
	integer.

	i must be a string of numbers 0..255 separated by dots '.'::
	pre: forall([0 <= int(p) < 256 for p in i.split('.')])

	n is a number of bits to mask::
	pre: 0 <= n <= 32

	Examples:
	>>> bin2addr(cidr('192.168.5.45', 32))
	'192.168.5.45'
	>>> bin2addr(cidr('192.168.5.45', 24))
	'192.168.5.0'
	>>> bin2addr(cidr('192.168.0.45', 8))
	'192.0.0.0'
	"""
	return ~(MASK >> n) & MASK & addr2bin(i)

def addr2bin(str):
	"""Convert a string IPv4 address into an unsigned integer.

	Examples::
	>>> addr2bin('127.0.0.1')
	2130706433L

	>>> addr2bin('127.0.0.1') == socket.INADDR_LOOPBACK
	1

	>>> addr2bin('255.255.255.254')
	4294967294L

	>>> addr2bin('192.168.0.1')
	3232235521L

	Unlike DNS.addr2bin, the n, n.n, and n.n.n forms for IP addresses
	are handled as well::
	>>> addr2bin('10.65536')
	167837696L
	>>> 10 * (2 ** 24) + 65536
	167837696

	>>> addr2bin('10.93.512')
	173867520L
	>>> 10 * (2 ** 24) + 93 * (2 ** 16) + 512
	173867520
	"""
	return struct.unpack("!L", socket.inet_aton(str))[0]

def bin2addr(addr):
	"""Convert a numeric IPv4 address into string n.n.n.n form.

	Examples::
	>>> bin2addr(socket.INADDR_LOOPBACK)
	'127.0.0.1'

	>>> bin2addr(socket.INADDR_ANY)
	'0.0.0.0'

	>>> bin2addr(socket.INADDR_NONE)
	'255.255.255.255'
	"""
	return socket.inet_ntoa(struct.pack("!L", addr))

def expand_one(expansion, str, joiner):
	if not str:
		return expansion
	len, reverse, delimiters = RE_ARGS.split(str)[1:4]
	if not delimiters:
		delimiters = '.'
	expansion = split(expansion, delimiters, joiner)
	if reverse: expansion.reverse()
	if len: expansion = expansion[-int(len)*2+1:]
	return ''.join(expansion)

def split(str, delimiters, joiner=None):
	"""Split a string into pieces by a set of delimiter characters.  The
	resulting list is delimited by joiner, or the original delimiter if
	joiner is not specified.

	Examples:
	>>> split('192.168.0.45', '.')
	['192', '.', '168', '.', '0', '.', '45']

	>>> split('terry@wayforward.net', '@.')
	['terry', '@', 'wayforward', '.', 'net']

	>>> split('terry@wayforward.net', '@.', '.')
	['terry', '.', 'wayforward', '.', 'net']
	"""
	result, element = [], ''
	for c in str:
		if c in delimiters:
			result.append(element)
			element = ''
			if joiner:
				result.append(joiner)
			else:
				result.append(c)
		else:
			element += c
	result.append(element)
	return result

def _test():
	import doctest, spf
	return doctest.testmod(spf)

DNS.DiscoverNameServers() # Fails on Mac OS X? Add domain to /etc/resolv.conf

if __name__ == '__main__':
	import sys
	if len(sys.argv) == 1:
		print USAGE
		_test()
	elif len(sys.argv) == 2:
		q = query(i='127.0.0.1', s='localhost', h='unknown')
		print q.dns_spf(sys.argv[1])
	elif len(sys.argv) == 4:
		print check(i=sys.argv[1], s=sys.argv[2], h=sys.argv[3])
	elif len(sys.argv) == 5:
		i, s, h = sys.argv[2:]
		q = query(i=i, s=s, h=h)
		print q.check(sys.argv[1])
	else:
		print USAGE
