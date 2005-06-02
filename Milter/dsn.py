# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2005 Business Management Systems, Inc.
# This code is under the GNU General Public License.  See COPYING for details.

# Send DSNs, do call back verification,
# and generate DSN messages from a template

import smtplib
import spf
import socket
from email.Message import Message

nospf_msg = """Subject: Critical mail server configuration error

This is an automatically generated Delivery Status Notification.

THIS IS A WARNING MESSAGE ONLY.

YOU DO *NOT* NEED TO RESEND YOUR MESSAGE.

Delivery to the following recipients has been delayed.

	%(rcpt)s

Subject: %(subject)s 

Someone at IP address %(connectip)s sent an email claiming
to be from %(sender)s.  

If that wasn't you, then your domain, %(sender_domain)s,
was forged - i.e. used without your knowlege or authorization by
someone attempting to steal your mail identity.  This is a very
serious problem, and you need to provide authentication for your
SMTP (email) servers to prevent criminals from forging your
domain.  The simplest step is usually to publish an SPF record
with your Sender Policy.  

For more information, see: http://spfhelp.net

I hate to annoy you with a DSN (Delivery Status
Notification) from a possibly forged email, but since you
have not published a sender policy, there is no other way
of bringing this to your attention.

If it *was* you that sent the email, then your email domain
or configuration is in error.  If you don't know anything
about mail servers, then pass this on to your SMTP (mail)
server administrator.  We have accepted the email anyway, in
case it is important, but we couldn't find anything about
the mail submitter at %(connectip)s to distinguish it from a
zombie (compromised/infected computer - usually a Windows
PC).  There was no PTR record for its IP address (PTR names
that contain the IP address don't count).  RFC2821 requires
that your hello name be a FQN (Fully Qualified domain Name,
i.e. at least one dot) that resolves to the IP address of
the mail sender.  In addition, just like for PTR, we don't
accept a helo name that contains the IP, since this doesn't
help to identify you.  The hello name you used,
%(heloname)s, was invalid.

Furthermore, there was no SPF record for the sending domain
%(sender_domain)s.  We even tried to find its IP in any A or
MX records for your domain, but that failed also.  We really
should reject mail from anonymous mail clients, but in case
it is important, we are accepting it anyway.

We are sending you this message to alert you to the fact that

Either - Someone is forging your domain.
Or - You have problems with your email configuration.
Or - Possibly both.

If you need further assistance, please do not hesitate to
contact me again.

Kind regards,

postmaster@%(receiver)s
"""

softfail_msg = """Subject: SPF softfail (POSSIBLE FORGERY)

This is an automatically generated Delivery Status Notification.

THIS IS A WARNING MESSAGE ONLY.

YOU DO *NOT* NEED TO RESEND YOUR MESSAGE.

Delivery to the following recipients has been delayed.

       %(rcpt)s

Subject: %(subject)s
Received-SPF: %(spf_result)s
"""

def send_dsn(mailfrom,receiver,msg=None):
  "Send DSN.  If msg is None, do callback verification."
  user,domain = mailfrom.split('@')
  q = spf.query(None,None,None)
  mxlist = q.dns(domain,'MX')
  if not mxlist:
    mxlist = (0,domain),
  else:
    mxlist.sort()
  smtp = smtplib.SMTP()
  for prior,host in mxlist:
    try:
      smtp.connect(host)
      code,resp = smtp.helo(receiver)
      # some wiley spammers have MX records that resolve to 127.0.0.1
      if resp.split()[0] == receiver:
        return (553,'Fraudulent MX for %s' % domain)
      if not (200 <= code <= 299):
	raise SMTPHeloError(code, resp)
      if msg:
        try:
	  smtp.sendmail('<>',mailfrom,msg)
	except smtplib.SMTPSenderRefused:
	  # does not accept DSN, try postmaster (at the risk of mail loops)
	  smtp.sendmail('<postmaster@%s>'%receiver,mailfrom,msg)
      else:	# CBV
	code,resp = smtp.docmd('MAIL FROM: <>')
	if code != 250:
	  raise SMTPSenderRefused(code, resp, '<>')
	code,resp = smtp.rcpt(mailfrom)
	if code not in (250,251):
	  return (code,resp)		# permanent error
	smtp.quit()
      return None			# success
    except smtplib.SMTPRecipientsRefused,x:
      return x.recipients[mailfrom]	# permanent error
    except smtplib.SMTPSenderRefused,x:
      return x		# does not accept DSN
    except smtplib.SMTPDataError,x:
      return x				# permanent error
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
  rcpt = '\n\t'.join(rcptlist)
  try: subject = origmsg['Subject']
  except: subject = '(none)'
  try:
    spf_result = origmsg['Received-SPF']
    if not spf_result.startswith('softfail'):
      spf_result = None
  except: spf_result = None

  msg = Message()

  msg.add_header('To',sender)
  msg.add_header('From','postmaster@%s'%receiver)
  msg.add_header('Auto-Submitted','auto-generated (configuration error)')
  msg.set_type('text/plain')

  if not template:
    if spf_result: template = softfail_msg
    else: template = nospf_msg
  hdrs,body = template.split('\n',1)
  for ln in hdrs.splitlines():
    name,val = ln.split(':',1)
    msg.add_header(name,(val % locals()).strip())
  msg.set_payload(body % locals())

  return msg

if __name__ == '__main__':
  q = spf.query('192.168.9.50',
  'SRS0=pmeHL=RH=bmsi.com=stuart@bmsi.com',
  'bmsred.bmsi.com',receiver='mail.bmsi.com')
  msg = create_msg(q,['charlie@jsconnor.com'],None,None)
  print msg.as_string()
  # print send_dsn(f,msg.as_string())
  print send_dsn(q.s,'mail.bmsi.com',msg.as_string())
