# Email address list with expiration
#
# This class acts like a map.  Entries with a value of None are persistent,
# but disappear after a time limit.  This is useful for automatic whitelists
# and blacklists with expiration.  The persistent store is a simple ascii
# file with sender and timestamp on each line.  Entries can be appended
# to the store, and will be picked up the next time it is loaded.
#
# Entries with other values are not persistent.  This is used to hold failed
# CBV results.
#
# $Log$

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2002,2003,2004,2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

import time

class AddrCache(object):
  time_format = '%Y%b%d %H:%M:%S %Z'

  def __init__(self,renew=7,fname=None):
    self.age = renew
    self.cache = {}
    self.fname = fname

  def load(self,fname,age=0):
    "Load address cache from persistent store."
    if not age:
      age = self.age
    self.fname = fname
    cache = {}
    self.cache = cache
    now = time.time()
    try:
      too_old = now - age*24*60*60	# max age in days
      for ln in open(self.fname):
	try:
	  rcpt,ts = ln.strip().split(None,1)
	  l = time.strptime(ts,AddrCache.time_format)
	  t = time.mktime(l)
	  if t > too_old:
	    cache[rcpt.lower()] = (t,None)
	except:
	  cache[ln.strip().lower()] = (now,None)
    except IOError: pass

  def has_key(self,sender):
    "True if sender is cached and has not expired."
    try:
      lsender = sender.lower()
      ts,res = self.cache[lsender]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if not ts or ts > too_old:
        return True
      del self.cache[lsender]
      try:
	user,host = sender.split('@',1)
	return self.has_key(host)
      except ValueError:
        pass
    except KeyError:
      try:
	user,host = sender.split('@',1)
	return self.has_key(host)
      except ValueError:
        pass
    return False

  def __getitem__(self,sender):
    try:
      lsender = sender.lower()
      ts,res = self.cache[lsender]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if not ts or ts > too_old:
	return res
      del self.cache[lsender]
      raise KeyError, sender
    except KeyError,x:
      try:
	user,host = sender.split('@',1)
	return self.__getitem__(host)
      except ValueError:
        raise x

  def addperm(self,sender,res=None):
    "Add a permanent sender."
    lsender = sender.lower()
    if self.has_key(lsender):
      ts,res = self.cache[lsender]
      if not ts: return		# already permanent
    self.cache[lsender] = (None,res)
    if not res:
      print >>open(self.fname,'a'),sender
    
  def __setitem__(self,sender,res):
    lsender = sender.lower()
    now = time.time()
    cached = self.has_key(sender)
    if not cached:
      self.cache[lsender] = (now,res)
      if not res and self.fname:
	s = time.strftime(AddrCache.time_format,time.localtime(now))
	print >>open(self.fname,'a'),sender,s # log refreshed senders

  def __len__(self):
    return len(self.cache)
