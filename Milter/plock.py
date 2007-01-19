# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2001 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

import os
from time import sleep

class PLock(object):
  "A simple /etc/passwd style lock,update,rename protocol for updating files."
  def __init__(self,basename):
    self.basename = basename
    self.fp = None

  def lock(self,lockname=None,mode=0660,strict_perms=False):
    "Start an update transaction.  Return FILE to write new version."
    self.unlock()
    if not lockname:
      lockname = self.basename + '.lock'
    self.lockname = lockname
    try:
      st = os.stat(self.basename)
      mode |= st.st_mode
    except OSError: pass
    u = os.umask(0002)
    try:
      fd = os.open(lockname,os.O_WRONLY+os.O_CREAT+os.O_EXCL,mode)
    finally:
      os.umask(u)
    self.fp = os.fdopen(fd,'w')
    try:
      os.chown(self.lockname,-1,st.st_gid)
    except:
      if strict_perms:
	self.unlock()
	raise
    return self.fp

  def wlock(self,lockname=None):
    "Wait until lock is free, then start an update transaction."
    while True:
      try:
        return self.lock(lockname)
      except OSError:
        sleep(2)

  def commit(self,backname=None):
    "Commit update transaction with optional backup file."
    if not self.fp:
      raise IOError,"File not locked"
    self.fp.close()
    self.fp = None
    if backname:
      try:
	os.remove(backname)
      except OSError: pass
      os.link(self.basename,backname)
    os.rename(self.lockname,self.basename)

  def unlock(self):
    "Cancel update transaction."
    if self.fp:
      try:
        self.fp.close()
      except: pass
      self.fp = None
      os.remove(self.lockname)
