# Abstract

This is a python extension module to enable python scripts to attach to
Sendmail's libmilter API, enabling filtering of messages as they arrive.
Since it's a script, you can do anything you want to the message - screen
out viruses, collect statistics, add or modify headers, etc.  You can, at
any point, tell Sendmail to reject, discard, or accept the message.

Additional python modules provide for navigating and modifying MIME parts, and
sending DSNs or doing CBVs.

# Requirements 

Python milter extension: https://pypi.org/project/pymilter/
Python: http://www.python.org
Sendmail: http://www.sendmail.org
   or
Postfix: http://www.postfix.org/MILTER_README.html

# Quick Installation

 1. Build and install Sendmail, enabling libmilter (see libmilter/README).
 2. Build and install Python, enabling threading.
 3. Install this module: python setup.py --help
 4. Add these two lines to sendmail.cf[a]:
```
 O InputMailFilters=pythonfilter
 Xpythonfilter,        S=local:/home/username/pythonsock
```
 5. Run the sample.py example milter with: python sample.py
 Note that milters should almost certainly not run as root.

That's it.  Incoming mail will cause the milter to print some things, and
some email will be rejected (see the "header" method).  Edit and play.  
See spfmilter.py for a functional SPF milter, or see bms.py for an complex
milter used in production.

[a] This is for a quick test.  Your sendmail.cf in most distros will get
overwritten whenever sendmail.mc is updated.  To make a milter permanent,
add something like:
```
INPUT_MAIL_FILTER(`pythonfilter', `S=local:/home/username/pythonsock, F=T, T=C:5m;S:20s;R:5m;E:5m')
```
to sendmail.mc instead.

# Not-so-quick Installation

First install Sendmail.  Make sure you read libmilter/README in the Sendmail
source directory, and make sure you enable libmilter before you build.  The
8.11 series had libmilter marked as FFR (For Future Release); 8.12
officially supports libmilter, but it's still not built by default.

Install Python, and enable threading in Modules/Setup.

Install this miltermodule package; DistUtils Automatic Installation:

$ python setup.py --help

Now that everything is installed, we need to tell sendmail that we're going
to filter incoming email.  Add lines similar to the following to
sendmail.cf:
```
O InputMailFilters=pythonfilter
Xpythonfilter,        S=local:/home/username/pythonsock
```
The "O" line tells sendmail which filters to use in what order; here we're
telling sendmail to use the filter named "pythonfilter".

The next line, the "X" line (for "eXternal"), lists that filter along with
some options associated with it.  In this case, we have the "S" option, which
names the socket that sendmail will use to communicate with this particular
milter.  This milter's socket is a unix-domain socket in the filesystem.
See libmilter/README for the definitive list of options.

NB: The name is specified in two places: here, in sendmail's cf file, and
in the milter itself.  Make sure the two match.

NB: The above lines can be added in your .mc file with this line:
```
INPUT_MAIL_FILTER(`pythonfilter', `S=local:/home/username/pythonsock')
```
For versions of sendmail prior to 8.12, you will need to enable
`_FFR_MILTER` for the cf macros.  For example,
```
m4 -D_FFR_MILTER ../m4/cf.m4 myconfig.mc > myconfig.cf
```
# IPv6 Notes

The IPv6 protocol is supported if your operation system supports it
and if sendmail was compiled with IPv6 support.  To determine if your
sendmail supports IPv6, run "sendmail -d0" and check for the NETINET6
compilation option.  To compile sendmail with IPv6 support, add this
declaration to your site.config.m4 before building it:
```
APPENDDEF(`confENVDEF', `-DNETINET6=1')
```
IPv6 support can show up in two places; the communications socket
between the milter and sendmail processes and in the host address
argument to the connect() callback method.

For sendmail to be able to accept IPv6 SMTP sessions, you must
configure the daemon to listen on an IPv6 port.  Furthermore if you
want to allow both IPv4 and IPv6 connections, some operating systems
will require that each listens to different port numbers.  For an
IPv6-only setup, your sendmail configuration should contain a line
similar to (first line is for sendmail.mc, second is sendmail.cf):
```
DAEMON_OPTIONS(`Name=MTA-v6, Family=inet6, Modify=C, Port=25')
O DaemonPortOptions=Name=MTA-v6, Family=inet6, Modify=C, Port=25
```
To allow sendmail and the milter process to communicate with each
other over IPv6, you may use the "inet6" socket name prefix, as in:
```
Xpythonfilter,        S=inet6:1234@fec0:0:0:7::5c
```
The connect() callback method in the milter class will pass the
IPv6-specific information in the 'hostaddr' argument as a tuple.  Note
that the type of this value is dependent upon the protocol family, and
is not compatible with IPv4 connections.  Therefore you should always
check the family argument before attempting to use the hostaddr
argument.  A quick example showing this follows:
```
  import socket
  
  class ipv6awareMilter(Milter.Milter):
     
     def connect(self,hostname,family,hostaddr):
	if family==socket.AF_INET:
	   ipaddress, port = hostaddr
	elif family==socket.AF_INET6:
	   ip6address, port, flowinfo, scopeid = hostaddr
	elif family==socket.AF_UNIX:
	   socketpath = hostaddr
```
The hostname argument is always safe to use without interpreting the
protocol family.  For IPv6 connections for which the hostname can not
be determined the hostname will appear similar to the string
"[IPv6:::1]" with the corresponding hostaddr[0] being "::1".  Refer to
RFC 2553 for information on interpreting and using the flowinfo and
scopeid socket attributes, both of which are integers.

# Authors

Jim Niemira (urmane@urmane.org) wrote the original C module and some quick
and dirty python to use it.  Stuart D. Gathman (stuart@gathman.org) took that
kludge and added threading and context objects to it, wrote a proper OO
wrapper (Milter.py) that handles attachments, did lots of testing, packaged
it with distutils, and generally transformed it from a quick hack to a
real, usable Python extension.
