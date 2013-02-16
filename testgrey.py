import unittest
import doctest
import os
#from Milter.greylist import Greylist
from Milter.greysql import Greylist

class GreylistTestCase(unittest.TestCase):

  def setUp(self):
    self.fname = 'test.db'
    os.remove(self.fname)

  def tearDown(self):
    #os.remove(self.fname)
    pass

  def testGrey(self):
    grey = Greylist(self.fname)
    # first time
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com')
    self.assertEqual(rc,0)
    # not in window yet
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=5*60)
    self.assertEqual(rc,0)
    # within window
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=15*60)
    self.assertEqual(rc,1)
    # new triple
    rc = grey.check('1.2.3.5','foo@bar.com','baz@spat.com',timeinc=15*60)
    self.assertEqual(rc,0)
    # seen again
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=5*3600)
    self.assertEqual(rc,2)
    # new one past expire
    rc = grey.check('1.2.3.5','foo@bar.com','baz@spat.com',timeinc=6*3600)
    self.assertEqual(rc,0)
    # original past retain 
    rc = grey.check('1.2.3.4','foo@bar.com','baz@spat.com',timeinc=37*24*3600)
    self.assertEqual(rc,0)
    # new one for testing expire
    rc = grey.check('1.2.3.5','flub@bar.com','baz@spat.com',timeinc=20*24*3600)
    self.assertEqual(rc,0)
    grey.close()
    # test cleanup
    grey = Greylist(self.fname)
    rc = grey.clean(timeinc=37*24*3600)
    self.assertEqual(rc,1)
    grey.close()

def suite(): 
  s = unittest.makeSuite(GreylistTestCase,'test')
  return s

if __name__ == '__main__':
  unittest.TextTestRunner().run(suite())
