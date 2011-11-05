## A very simple milter to prevent mixing of internal and external mail.  
# Internal is defined as using one of a list of internal top level domains.
#  This code is open-source on the same terms as Python.

import Milter
import time
import sys
from Milter.utils import parse_addr

internal_tlds = ["corp", "personal"]

## Determine if a hostname is internal or not. 
# True if internal, False otherwise
def is_internal(hostname):
    components = hostname.split(".")
    return components.pop() in internal_tlds:

# Determine if internal and external hosts are mixed based on a list
# of hostnames
def are_mixed(hostnames):
    hostnames_mapped = map(is_internal, hostnames)

    # Num internals
    num_internal_hosts = hostnames_mapped.count(True)

    # Num externals
    num_external_hosts = hostnames_mapped.count(False)

    return num_external_hosts >= 1 and num_internal_hosts >= 1

class NoMixMilter(Milter.Base):

  def __init__(self):  # A new instance with each new connection.
    self.id = Milter.uniqueID()  # Integer incremented with each call.


  ##  def envfrom(self,f,*str):
  @Milter.noreply
  def envfrom(self, mailfrom, *str):
    self.mailfrom = mailfrom
    self.domains = []
    t = parse_addr(mailfrom)
    if len(t) > 1:
      self.domains.append(t[1])
    else:
      self.domains.append('local')
    self.internal = False
    return Milter.CONTINUE

  ##  def envrcpt(self, to, *str):
  def envrcpt(self, to, *str):
    self.R.append(to)
    t = parse_addr(to)
    if len(t) > 1:
      self.domains.append(t[1])
    else:
      self.domains.append('local')

    if are_mixed(self.domains):
      # FIXME: log recipients collected in self.mailfrom and self.R
      self.setreply('550','5.7.1','Mixing internal and external TLDs')
      return Milter.REJECT
        
    return Milter.CONTINUE
    
def main():
  socketname = "/var/run/nomixsock"
  timeout = 600
  # Register to have the Milter factory create instances of your class:
  Milter.factory = NoMixMilter
  print "%s milter startup" % time.strftime('%Y%b%d %H:%M:%S')
  sys.stdout.flush()
  Milter.runmilter("nomixfilter",socketname,timeout)
  logq.put(None)
  bt.join()
  print "%s nomix milter shutdown" % time.strftime('%Y%b%d %H:%M:%S')

if __name__ == "__main__":
  main()
