import unittest
import os

from Milter.cache import AddrCache

class AddrCacheTestCase(unittest.TestCase):

  def setUp(self):
    self.fname = 'test.dat'
    self.cache = AddrCache(fname=self.fname)

  def tearDown(self):
    os.remove(self.fname)

  def testAdd(self):
    cache = self.cache
    cache['foo@bar.com'] = None
    cache.addperm('baz@bar.com')
    cache['temp@bar.com'] = 'testing'
    self.failUnless(cache.has_key('foo@bar.com'))
    self.failUnless(not cache.has_key('hello@bar.com'))
    self.failUnless('baz@bar.com' in cache)
    self.assertEquals(cache['temp@bar.com'],'testing')
    s = open(self.fname).readlines()
    self.failUnless(len(s) == 2)
    self.failUnless(s[0].startswith('foo@bar.com '))
    self.assertEquals(s[1].strip(),'baz@bar.com')

def suite(): return unittest.makeSuite(AddrCacheTestCase,'test')

if __name__ == '__main__':
  unittest.main()
