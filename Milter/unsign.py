# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# The localpart of SMTP return addresses is often signed.  The format
# of the signing is application specific and doesn't concern us -
# except that we wish to extract some sort of fixed string from
# the variable signature which represents the "source" of the message.

def unsign(s):
  """Attempt to unsign localpart and return original email.
  No attempt is made to verify the signature.
  >>> unsign('SRS0=8Y3CZ=3U=jsconnor.com=bills@bmsi.com')
  'bills@jsconnor.com'
  """
  # not implemented yet
  return s
