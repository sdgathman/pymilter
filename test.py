import unittest
import testmime
import testsample
import testutils
import testgrey
import testcfg
import os

def suite(): 
  s = unittest.TestSuite()
  s.addTest(testmime.suite())
  s.addTest(testsample.suite())
  s.addTest(testutils.suite())
  s.addTest(testgrey.suite())
  s.addTest(testcfg.suite())
  return s

if __name__ == '__main__':
  try: os.remove('test/milter.log')
  except: pass
  unittest.TextTestRunner().run(suite())
