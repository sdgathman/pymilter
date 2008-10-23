from ConfigParser import ConfigParser

class MilterConfigParser(ConfigParser):

  def __init__(self,defaults={}):
    ConfigParser.__init__(self)
    self.defaults = defaults

  # The defaults provided by ConfigParser show up in all sections,
  # which screws up iterating over all options in a section.
  # Worse, passing "defaults" with vars= overrides the config file!
  # So we roll our own defaults.
  def get(self,sect,opt):
    if not self.has_option(sect,opt) and opt in self.defaults:
      return self.defaults[opt]
    return ConfigParser.get(self,sect,opt)
    
  def getlist(self,sect,opt):
    if self.has_option(sect,opt):
      return [q.strip() for q in self.get(sect,opt).split(',')]
    return []

  def getaddrset(self,sect,opt):
    if not self.has_option(sect,opt):
      return {}
    s = self.get(sect,opt)
    d = {}
    for q in s.split(','):
      q = q.strip()
      if q.startswith('file:'):
        domain = q[5:].lower()
	d[domain] = d.setdefault(domain,[]) + open(domain,'r').read().split()
      else:
	user,domain = q.split('@')
	d.setdefault(domain.lower(),[]).append(user)
    return d
  
  def getaddrdict(self,sect,opt):
    if not self.has_option(sect,opt):
      return {}
    d = {}
    for q in self.get(sect,opt).split(','):
      q = q.strip()
      if self.has_option(sect,q):
        l = self.get(sect,q)
	for addr in l.split(','):
	  addr = addr.strip()
	  if addr.startswith('file:'):
	    fname = addr[5:]
	    for a in open(fname,'r').read().split():
	      d[a] = q
	  else:
	    d[addr] = q
    return d

  def getdefault(self,sect,opt,default=None):
    if self.has_option(sect,opt):
      return self.get(sect,opt)
    return default

  def getintdefault(self,sect,opt,default=None):
    if self.has_option(sect,opt):
      return self.getint(sect,opt)
    return default
