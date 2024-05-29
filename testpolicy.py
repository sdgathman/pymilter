from __future__ import print_function
import unittest
import sys
import os
from Milter.policy import MTAPolicy

class Config(object):
  def __init__(self):
    self.access_file='test/access.db'
    self.access_file_nulls=True

class PolicyTestCase(unittest.TestCase):

  def setUp(self):
    self.config = Config()
    if os.access('test/access',os.R_OK):
      if not os.path.exists('test/access.db') or \
          os.path.getmtime('test/access') > os.path.getmtime('test/access.db'):
        cmd = 'tr : ! <test/access | makemap hash test/access.db'
        if os.system(cmd):
          print('failed!')
    else:
      print("Missing test/access")

  def testPolicy(self):
    self.config.use_colon = True
    self.config.use_nulls = True
    with MTAPolicy('good@example.com',conf=self.config) as p:
      pol = p.getPolicy('smtp-auth')
    self.assertEqual(pol,'OK')
    with MTAPolicy('bad@example.com',conf=self.config) as p:
      pol = p.getPolicy('smtp-auth')
    self.assertEqual(pol,'REJECT')
    with MTAPolicy('bad@bad.example.com',conf=self.config) as p:
      pol = p.getPolicy('smtp-auth')
    self.assertEqual(pol,None)
    with MTAPolicy('any@random.com',conf=self.config) as p:
      pol = p.getPolicy('smtp-test')
    self.assertEqual(pol,'REJECT')
    with MTAPolicy('foo@bar.baz.com',conf=self.config) as p:
      pol = p.getPolicy('smtp-test')
    self.assertEqual(pol,'WILDCARD')

def suite(): return unittest.makeSuite(PolicyTestCase,'test')

if __name__ == '__main__':
  if len(sys.argv) < 2:
    unittest.main()
  else:
    a = sys.argv[1:]
    while len(a) >= 2:
      e,k = a[:2]
      with MTAPolicy(e,conf=Config()) as p:
        pol = p.getPolicy(k)
        print(pol)
      a = a[2:]
