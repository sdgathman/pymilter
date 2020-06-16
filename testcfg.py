import unittest
from Milter.config import MilterConfigParser

class ConfigTestCase(unittest.TestCase):
  def testConfig(self):
    cp = MilterConfigParser()
    cp.read(['test/pysrs.cfg'])
    socketname = cp.getdefault('srsmilter','socketname',
        '/var/run/milter/srsmilter')
    self.assertEqual(socketname,'/var/run/milter/srsmilter')

def suite(): return unittest.makeSuite(ConfigTestCase,'test')

if __name__ == '__main__':
  unittest.main()
