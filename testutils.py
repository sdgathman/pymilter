import unittest
import doctest
import os
import Milter.utils
from Milter.cache import AddrCache
from Milter.dynip import is_dynip

class AddrCacheTestCase(unittest.TestCase):

  def setUp(self):
    self.fname = 'test.dat'

  def tearDown(self):
    os.remove(self.fname)

  def testAdd(self):
    cache = AddrCache(fname=self.fname)
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
    # check that new result overrides old
    cache['temp@bar.com'] = None
    self.failUnless(not cache['temp@bar.com'])

  def testDomain(self):
    fp = open(self.fname,'w')
    print >>fp,'spammer.com'
    fp.close()
    cache = AddrCache(fname=self.fname)
    cache.load(self.fname,30)
    self.failUnless('spammer.com' in cache)

def suite(): 
  s = unittest.makeSuite(AddrCacheTestCase,'test')
  s.addTest(doctest.DocTestSuite(Milter.utils))
  s.addTest(doctest.DocTestSuite(Milter.dynip))
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
