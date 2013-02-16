import unittest
import doctest
import os
import Milter.greylist
from Milter.greylist import Greylist

class GreylistTestCase(unittest.TestCase):

  def setUp(self):
    self.fname = 'test.db'

  def tearDown(self):
    os.remove(self.fname)

  def testGrey(self):
    grey = Greylist(self.fname)
    # first time
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com')
    self.failUnless(rc == 0)
    # not in window yet
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=5*60)
    self.failUnless(rc == 0)
    # within window
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=15*60)
    self.failUnless(rc == 1)
    # new triple
    rc = grey.check('1.2.3.5','foo@bar.com','baz@spat.com',timeinc=15*60)
    self.failUnless(rc == 0)
    # seen again
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=5*3600)
    self.failUnless(rc == 2)
    # new one past expire
    rc = grey.check('1.2.3.5','foo@bar.com','baz@spat.com',timeinc=5*3600)
    self.failUnless(rc == 0)
    # original past retain 
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=37*24*3600)
    self.failUnless(rc == 0)

def suite(): 
  s = unittest.makeSuite(GreylistTestCase,'test')
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
