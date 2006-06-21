# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# Send DSNs, do call back verification,
# and generate DSN messages from a template
# $Log$
# Revision 1.10  2006/05/24 20:56:35  customdesigned
# Remove default templates.  Scrub test.
#

import smtplib
import spf
import socket
from email.Message import Message
import Milter

def send_dsn(mailfrom,receiver,msg=None):
  """Send DSN.  If msg is None, do callback verification.
     Mailfrom is original sender we are sending DSN or CBV to.
     Receiver is the MTA sending the DSN.
     Return None for success or (code,msg) for failure."""
  user,domain = mailfrom.split('@')
  q = spf.query(None,None,None)
  mxlist = q.dns(domain,'MX')
  if not mxlist:
    mxlist = (0,domain),	# fallback to A record when no MX
  else:
    mxlist.sort()
  smtp = smtplib.SMTP()
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
	  smtp.sendmail('<>',mailfrom,msg)
	except smtplib.SMTPSenderRefused:
	  # does not accept DSN, try postmaster (at the risk of mail loops)
	  smtp.sendmail('<postmaster@%s>'%receiver,mailfrom,msg)
      else:	# CBV
	code,resp = smtp.docmd('MAIL FROM: <>')
	if code != 250:
	  raise smtplib.SMTPSenderRefused(code, resp, '<>')
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
    smtp.close()
  return (450,'No MX servers available')	# temp error

def create_msg(q,rcptlist,origmsg=None,template=None):
  "Create a DSN message from a template.  Template must be '\n' separated."
  heloname = q.h
  sender = q.s
  connectip = q.i
  receiver = q.r
  sender_domain = q.o
  result = q.result
  perm_error = q.perm_error
  rcpt = '\n\t'.join(rcptlist)
  try: subject = origmsg['Subject']
  except: subject = '(none)'
  try:
    spf_result = origmsg['Received-SPF']
  except: spf_result = None

  msg = Message()

  msg.add_header('X-Mailer','PyMilter-'+Milter.__version__)
  msg.set_type('text/plain')

  if not template:
    if spf_result and spf_result.startswith('softfail'):
      template = softfail_msg
    else:
      template = nospf_msg
  hdrs,body = template.split('\n\n',1)
  for ln in hdrs.splitlines():
    name,val = ln.split(':',1)
    msg.add_header(name,(val % locals()).strip())
  msg.set_payload(body % locals())
  # add headers if missing from old template
  if 'to' not in msg:
    msg.add_header('To',sender)
  if 'from' not in msg:
    msg.add_header('From','postmaster@%s'%receiver)
  if 'auto-submitted' not in msg:
    msg.add_header('Auto-Submitted','auto-generated')
  return msg

if __name__ == '__main__':
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
