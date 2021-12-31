import os
import sys
from setuptools import setup, Extension

if sys.version < '2.6.5':
  sys.exit('ERROR: Sorry, python 2.6.5 is required for this module.')

with open("README.md", "r") as fh:
    long_description = fh.read()

# FIXME: on some versions of sendmail, smutil is renamed to sm.
# On slackware and debian, leave it out entirely.  It depends
# on how libmilter was built by the sendmail package.
#libs = ["milter", "smutil"]
libs = ["milter"]
libdirs = ["/usr/lib/libmilter"]    # needed for Debian
modules = ["mime"]

# NOTE: importing Milter to obtain version fails when milter.so not built
setup(name = "pymilter", version = '1.0.5',
	description="Python interface to sendmail milter API",
	long_description=long_description,
    long_description_content_type='text/markdown',
	author="Jim Niemira",
	author_email="urmane@urmane.org",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@gathman.org",
	license="GPL",
	url="https://www.pymilter.org/",
	py_modules=modules,
	packages = ['Milter'],
	ext_modules=[
	  Extension("milter", ["miltermodule.c"],
            library_dirs=libdirs,
	    libraries=libs,
	    # set MAX_ML_REPLY to 1 for sendmail < 8.13
	    define_macros = [ ('MAX_ML_REPLY',32) ],
            # save lots of debugging time testing rfc2553 compliance
            extra_compile_args = [ "-Werror=implicit-function-declaration" ]
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
