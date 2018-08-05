from __future__ import print_function
import unittest
import doctest
import os
import Milter.utils
from Milter.cache import AddrCache
from Milter.dynip import is_dynip
from Milter.pyip6 import inet_ntop

class AddrCacheTestCase(unittest.TestCase):

  def setUp(self):
    self.fname = 'test.dat'

  def tearDown(self):
    if os.path.exists(self.fname):
      os.remove(self.fname)

  def testAdd(self):
    cache = AddrCache(fname=self.fname)
    cache['foo@bar.com'] = None
    cache.addperm('baz@bar.com')
    cache['temp@bar.com'] = 'testing'
    self.assertTrue(cache.has_key('foo@bar.com'))
    self.assertTrue(not cache.has_key('hello@bar.com'))
    self.assertTrue('baz@bar.com' in cache)
    self.assertEquals(cache['temp@bar.com'],'testing')
    s = open(self.fname).readlines()
    self.assertTrue(len(s) == 2)
    self.assertTrue(s[0].startswith('foo@bar.com '))
    self.assertEquals(s[1].strip(),'baz@bar.com')
    # check that new result overrides old
    cache['temp@bar.com'] = None
    self.assertTrue(not cache['temp@bar.com'])

  def testDomain(self):
    with open(self.fname,'w') as fp:
      print('spammer.com',file=fp)
    cache = AddrCache(fname=self.fname)
    cache.load(self.fname,30)
    self.assertTrue('spammer.com' in cache)

  def testParseHeader(self):
    s='=?UTF-8?B?TGFzdCBGZXcgQ29sZHBsYXkgQWxidW0gQXJ0d29ya3MgQXZhaWxhYmxlAA?='
    h = Milter.utils.parse_header(s)
    self.assertEqual(h,b'Last Few Coldplay Album Artworks Available\x00')

  @unittest.expectedFailure
  def testParseAddress(self):
    s = Milter.utils.parseaddr('a(WRONG)@b')
    self.assertEqual(s,('WRONG', 'a@b'))

def suite(): 
  s = unittest.makeSuite(AddrCacheTestCase,'test')
  s.addTest(doctest.DocTestSuite(Milter.utils))
  s.addTest(doctest.DocTestSuite(Milter.dynip))
  s.addTest(doctest.DocTestSuite(Milter.pyip6))
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
