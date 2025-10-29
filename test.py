import unittest
import testmime
import testsample
import testutils
import testgrey
import testcfg
import testpolicy
import os

def suite(): 
  s = unittest.TestSuite()
  s.addTest(testmime.suite())
  s.addTest(testsample.suite())
  s.addTest(testutils.suite())
  s.addTest(testgrey.suite())
  s.addTest(testcfg.suite())
  s.addTest(testpolicy.suite())
  return s

if __name__ == '__main__':
  import sys
  try: os.remove('test/milter.log')
  except: pass
  rc = unittest.TextTestRunner().run(suite())
  sys.exit(0 if rc.wasSuccessful() else 1)
