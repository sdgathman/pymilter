# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# Send DSNs, do call back verification,
# and generate DSN messages from a template
# $Log$
# Revision 1.16  2007/09/25 01:24:59  customdesigned
# Allow arbitrary object, not just spf.query like, to provide data for create_msg
#
# Revision 1.15  2007/09/24 20:13:26  customdesigned
# Remove explicit spf dependency.
#
# Revision 1.14  2007/03/03 18:19:40  customdesigned
# Handle DNS error sending DSN.
#
# Revision 1.13  2007/01/04 18:01:11  customdesigned
# Do plain CBV when template missing.
#
# Revision 1.12  2006/07/26 16:37:35  customdesigned
# Support timeout.
#
# Revision 1.11  2006/06/21 21:07:11  customdesigned
# Include header fields in DSN template.
#
# Revision 1.10  2006/05/24 20:56:35  customdesigned
# Remove default templates.  Scrub test.
#

import smtplib
import socket
from email.Message import Message
import Milter
import time
import dns

def send_dsn(mailfrom,receiver,msg=None,timeout=600,session=None,ourfrom=''):
  """Send DSN.  If msg is None, do callback verification.
     Mailfrom is original sender we are sending DSN or CBV to.
     Receiver is the MTA sending the DSN.
     Return None for success or (code,msg) for failure."""
  user,domain = mailfrom.split('@')
  if not session: session = dns.Session()
  try:
    mxlist = session.dns(domain,'MX')
  except dns.DNSError:
    return (450,'DNS Timeout: %s MX'%domain)	# temp error
  if not mxlist:
    mxlist = (0,domain),	# fallback to A record when no MX
  else:
    mxlist.sort()
  smtp = smtplib.SMTP()
  toolate = time.time() + timeout
  for prior,host in mxlist:
    try:
      smtp.connect(host)
      code,resp = smtp.helo(receiver)
      # some wiley spammers have MX records that resolve to 127.0.0.1
      a = resp.split()
      if not a:
        return (553,'MX for %s has no hostname in banner: %s' % (domain,host))
      if a[0] == receiver:
        return (553,'Fraudulent MX for %s: %s' % (domain,host))
      if not (200 <= code <= 299):
	raise smtplib.SMTPHeloError(code, resp)
      if msg:
        try:
	  smtp.sendmail('<%s>'%ourfrom,mailfrom,msg)
	except smtplib.SMTPSenderRefused:
	  # does not accept DSN, try postmaster (at the risk of mail loops)
	  smtp.sendmail('<postmaster@%s>'%receiver,mailfrom,msg)
      else:	# CBV
	code,resp = smtp.docmd('MAIL FROM: <%s>'%ourfrom)
	if code != 250:
	  raise smtplib.SMTPSenderRefused(code, resp, '<%s>'%ourfrom)
	code,resp = smtp.rcpt(mailfrom)
	if code not in (250,251):
	  return (code,resp)		# permanent error
	smtp.quit()
      return None			# success
    except smtplib.SMTPRecipientsRefused,x:
      return x.recipients[mailfrom]	# permanent error
    except smtplib.SMTPSenderRefused,x:
      return x.args[:2]			# does not accept DSN
    except smtplib.SMTPDataError,x:
      return x.args			# permanent error
    except smtplib.SMTPException:
      pass		# any other error, try next MX
    except socket.error:
      pass		# MX didn't accept connections, try next one
    except socket.timeout:
      pass		# MX too slow, try next one
    smtp.close()
    if time.time() > toolate:
      return (450,'No MX response within %f minutes'%(timeout/60.0))
  return (450,'No MX servers available')	# temp error

class Vars: pass

# NOTE: Caller can pass an object to create_msg that in a typical milter
# collects things like heloname or sender anyway.
def create_msg(v,rcptlist=None,origmsg=None,template=None):
  """Create a DSN message from a template.  Template must be '\n' separated.
     v - an object whose attributes are used for substitutions.  Must
       have sender and receiver attributes at a minimum.
     rcptlist - used to set v.rcpt if given
     origmsg - used to set v.subject and v.spf_result if given
     template - a '\n' separated string with python '%(name)s' substitutions.
  """
  if not template:
    return None
  if hasattr(v,'perm_error'):
    # likely to be an spf.query, try translating for backward compatibility
    q = v
    v = Vars()
    try:
      v.heloname = q.h
      v.sender = q.s
      v.connectip = q.i
      v.receiver = q.r
      v.sender_domain = q.o
      v.result = q.result
      v.perm_error = q.perm_error
    except: v = q
  if rcptlist:
    v.rcpt = '\n\t'.join(rcptlist)
  if origmsg:
    try: v.subject = origmsg['Subject']
    except: v.subject = '(none)'
    try:
      v.spf_result = origmsg['Received-SPF']
    except: v.spf_result = None

  msg = Message()

  msg.add_header('X-Mailer','PyMilter-'+Milter.__version__)
  msg.set_type('text/plain')

  hdrs,body = template.split('\n\n',1)
  for ln in hdrs.splitlines():
    name,val = ln.split(':',1)
    msg.add_header(name,(val % v.__dict__).strip())
  msg.set_payload(body % v.__dict__)
  # add headers if missing from old template
  if 'to' not in msg:
    msg.add_header('To',v.sender)
  if 'from' not in msg:
    msg.add_header('From','postmaster@%s'%v.receiver)
  if 'auto-submitted' not in msg:
    msg.add_header('Auto-Submitted','auto-generated')
  return msg

if __name__ == '__main__':
  import spf
  q = spf.query('192.168.9.50',
  'SRS0=pmeHL=RH==stuart@example.com',
  'red.example.com',receiver='mail.example.com')
  q.result = 'softfail'
  q.perm_error = None
  msg = create_msg(q,['charlie@example.com'],None,
"""From: postmaster@%(receiver)s
To: %(sender)s
Subject: Test

Test DSN template
"""
  )
  print msg.as_string()
  # print send_dsn(f,msg.as_string())
  # print send_dsn(q.s,'mail.example.com',msg.as_string())
