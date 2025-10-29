from __future__ import print_function
import unittest
import sys
import os
import bsddb3
from Milter.policy import MTAPolicy

class Config(object):
  def __init__(self):
    self.access_file='test/access.db'
    self.access_file_nulls=True
    self.access_file_colon = False

def makemap(in_filename, out_filename):
  db = bsddb3.hashopen(out_filename, 'c')
  with open(in_filename, 'r', encoding='utf-8') as fh:
    for line in fh:
      line = line.strip().replace(":", "!")
      if not line or line.startswith("#"):
        continue
      [k, v] = line.split(maxsplit=1)
      db[k.lower().encode()] = v.encode()
  db.close()

class PolicyTestCase(unittest.TestCase):

  def setUp(self):
    self.config = Config()
    if os.access('test/access',os.R_OK):
      if not os.path.exists('test/access.db') or \
          os.path.getmtime('test/access') > os.path.getmtime('test/access.db'):
        makemap("test/access", "test/access.db")
    else:
      print("Missing test/access")

  def testPolicy(self):
    self.config.access_file_colon = False
    self.config.access_file_nulls = False   # FIXME: test old and new bsddb
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

def suite(): return unittest.TestLoader().loadTestsFromTestCase(PolicyTestCase)

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
