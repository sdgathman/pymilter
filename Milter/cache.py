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
# Revision 1.9  2008/05/08 21:35:57  customdesigned
# Allow explicitly whitelisted email from banned_users.
#
# Revision 1.8  2007/09/03 16:18:45  customdesigned
# Delete unparseable timestamps when loading address cache.  These have
# arisen because of failure to parse MAIL FROM properly.   Will have to
# tighten up MAIL FROM parsing to match RFC.
#
# Revision 1.7  2007/01/25 22:47:26  customdesigned
# Persist blacklisting from delayed DSNs.
#
# Revision 1.6  2007/01/19 23:31:38  customdesigned
# Move parse_header to Milter.utils.
# Test case for delayed DSN parsing.
# Fix plock when source missing or cannot set owner/group.
#
# Revision 1.5  2007/01/11 19:59:40  customdesigned
# Purge old entries in auto_whitelist and send_dsn logs.
#
# Revision 1.4  2007/01/11 04:31:26  customdesigned
# Negative feedback for bad headers.  Purge cache logs on startup.
#
# Revision 1.3  2007/01/08 23:20:54  customdesigned
# Get user feedback.
#
# Revision 1.2  2007/01/05 23:33:55  customdesigned
# Make blacklist an AddrCache
#
# Revision 1.1  2007/01/05 21:25:40  customdesigned
# Move AddrCache to Milter package.
#

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001,2002,2003,2004,2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

from __future__ import print_function
import time
from Milter.plock import PLock

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
    lock = PLock(self.fname)
    wfp = lock.lock()
    changed = False
    try:
      too_old = now - age*24*60*60	# max age in days
      try:
        fp = open(self.fname)
      except OSError:
        fp = ()
      for ln in fp:
        try:
          rcpt,ts = ln.strip().split(None,1)
          try:
            l = time.strptime(ts,AddrCache.time_format)
            t = time.mktime(l)
            if t < too_old:
              changed = True
              continue
            cache[rcpt.lower()] = (t,None)
          except:       # unparsable timestamp - likely garbage
            changed = True
            continue
        except: # manual entry (no timestamp)
          cache[ln.strip().lower()] = (now,None)
        wfp.write(ln)
      if changed:
        lock.commit(self.fname+'.old')
      else:
        lock.unlock()
    except IOError:
      lock.unlock()

  def has_precise_key(self,sender):
    """True if precise sender is cached and has not expired.  Don't
    try looking up wildcard entries.
    """
    try:
      lsender = sender and sender.lower()
      ts,res = self.cache[lsender]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if not ts or ts > too_old:
        return True
      del self.cache[lsender]
    except KeyError: pass
    return False

  def has_key(self,sender):
    "True if sender is cached and has not expired."
    if self.has_precise_key(sender):
      return True
    try:
      user,host = sender.split('@',1)
      return self.has_precise_key(host)
    except: pass
    return False

  __contains__ = has_key

  def __getitem__(self,sender):
    try:
      lsender = sender.lower()
      ts,res = self.cache[lsender]
      too_old = time.time() - self.age*24*60*60	# max age in days
      if not ts or ts > too_old:
        return res
      del self.cache[lsender]
      raise KeyError(sender)
    except KeyError as x:
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
      with open(self.fname,'a') as fp:
        print(sender,file=fp)
    
  def __setitem__(self,sender,res):
    lsender = sender.lower()
    now = time.time()
    self.cache[lsender] = (now,res)
    if not res and self.fname:
      s = time.strftime(AddrCache.time_format,time.localtime(now))
      with open(self.fname,'a') as fp:
        print(sender,s,file=fp) # log refreshed senders

  def __len__(self):
    return len(self.cache)
