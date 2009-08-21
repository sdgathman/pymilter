import os
import sys
from distutils.core import setup, Extension

# FIXME: on some versions of sendmail, smutil is renamed to sm.
# On slackware and debian, leave it out entirely.  It depends
# on how libmilter was built by the sendmail package.
#libs = ["milter", "smutil"]
libs = ["milter"]
libdirs = ["/usr/lib/libmilter"]    # needed for Debian

# patch distutils if it can't cope with the "classifiers" or
# "download_url" keywords
if sys.version < '2.2.3':
  from distutils.dist import DistributionMetadata
  DistributionMetadata.classifiers = None
  DistributionMetadata.download_url = None

# NOTE: importing Milter to obtain version fails when milter.so not built
setup(name = "pymilter", version = '0.9.3',
	description="Python interface to sendmail milter API",
	long_description="""\
This is a python extension module to enable python scripts to
attach to sendmail's libmilter functionality.  Additional python
modules provide for navigating and modifying MIME parts, and
sending DSNs or doing CBVs.
""",
	author="Jim Niemira",
	author_email="urmane@urmane.org",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@bmsi.com",
	license="GPL",
	url="http://www.bmsi.com/python/milter.html",
	py_modules=["mime"],
	packages = ['Milter'],
	ext_modules=[
	  Extension("milter", ["miltermodule.c"],
            library_dirs=libdirs,
	    libraries=libs,
	    # set MAX_ML_REPLY to 1 for sendmail < 8.13
	    define_macros = [ ('MAX_ML_REPLY',32) ]
	  ),
	],
	keywords = ['sendmail','milter'],
	classifiers = [
	  'Development Status :: 5 - Production/Stable',
	  'Environment :: No Input/Output (Daemon)',
	  'Intended Audience :: System Administrators',
	  'License :: OSI Approved :: GNU General Public License (GPL)',
	  'Natural Language :: English',
	  'Operating System :: POSIX',
	  'Programming Language :: Python',
	  'Topic :: Communications :: Email :: Mail Transport Agents',
	  'Topic :: Communications :: Email :: Filters'
	]
)
