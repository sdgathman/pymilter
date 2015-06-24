## @mainpage Writing Milters in Python
#
# At the lowest level, the <code>milter</code> module provides a thin wrapper
# around the <a href="milter_api/index.html"> sendmail
# libmilter API</a>.  This API lets you register callbacks for a number of
# events in the process of sendmail receiving a message via SMTP.  These
# events include the initial connection from a MTA, the envelope sender and
# recipients, the top level mail headers, and the message body.  There are
# options to mangle all of these components of the message as it passes through
# the %milter.
# 
# At the next level, the <code>Milter</code> module (note the case difference)
# provides a Python friendly object oriented wrapper for the low level API.  To
# use the Milter module, an application registers a 'factory' to create an
# object for each connection from a MTA to sendmail.  These connection objects
# must provide methods corresponding to the libmilter event callbacks.
# 
# Each callback method returns a code to tell sendmail whether to proceed with
# processing the message.  This is a big advantage of milters over other mail
# filtering systems.  Unwanted mail can be stopped in its tracks at the
# earliest possible point.  The callback return codes are
# milter.CONTINUE, milter.REJECT, milter.DISCARD, milter.ACCEPT, 
# milter.TEMPFAIL, milter.SKIP, milter.NOREPLY.
# 
# The Milter.Base class provides default implementations for
# event methods that do nothing, and also provides wrappers for the libmilter
# methods to mutate the message.  It automatically negotiates with MTA
# which protocol steps need to be processed by the %milter, based on
# which callback methods are overridden.
#
# The Milter.Milter class provides an alternate default
# implementation that logs the main milter callbacks, but otherwise does
# nothing.  It is provided for compatibility.
# 
# The mime module provides a wrapper for the Python email package
# that fixes some bugs, and simplifies modifying selected parts of a MIME
# message.
#
# @section threading
#
# The libmilter library which pymilter wraps 
# <a href="milter_overview#SignalHandling">handles
# all signals</a> itself, and expects to be called from a single main thread.
# It handles SIGTERM, SIGHUP, and SIGINT, mapping the first two to 
# <a href="milter_api/smfi_stop.html">smfi_stop</a>
# and the last to an internal ABORT.
#
# If you use python threads or threading modules, then signal handling gets
# confused.  Threads may still be useful, but you may need to provide an
# alternate means of causing graceful shutdown.
#
# You may find the
# <a href="http://docs.python.org/release/2.6.6/library/multiprocessing.html">
# multiprocessing</a> module useful.  It can be a drop-in
# replacement for threading as illustrated in 
# <a href="milter-template_8py-example.html">milter-template.py</a>.
#
# @section Useful python packages for milters
#
# <a href="https://pypi.python.org/pypi/pyspf">pyspf</a> checks the
# SMTP envelope sender (MAIL FROM, passed to the Milter.Base.envfrom callback)
# against a Sender Policy published in DNS by the sending domain.  This
# can prevent forgery of the MAIL FROM.  SPF is Sender Policy Framework.
#
# <a href="https://launchpad.net/dkimpy">pydkim</a> checks a DKIM signature
# of the email body and headers against a public key published in DNS by
# the signing domain.  DKIM is DomainKeys Identified Mail.
#
# The <a href="https://pypi.python.org/pypi/authres/">authres</a> module 
# parses and formats the Authentication-Results email header, providing
# a standard place to summarize the results from DKIM, SPF, rDNS, SMTP AUTH,
# and other email authentication methods.
#
# <a href="https://pypi.python.org/pypi/pydspam/">pydspam</a> wraps 
# the libdspam API of the <a href="http://dspam.sourceforge.net/">DSPAM</a>
# project.
