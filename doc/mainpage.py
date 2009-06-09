## @mainpage Writing Milters in Python
#
# 
# At the lowest level, the <code>milter</code> module provides a thin wrapper
# around the <a href="https://www.milter.org/developers/api/index"> sendmail
# libmilter API</a>.  This API lets you register callbacks for a number of
# events in the process of sendmail receiving a message via SMTP.  These
# events include the initial connection from a MTA, the envelope sender and
# recipients, the top level mail headers, and the message body.  There are
# options to mangle all of these components of the message as it passes through
# the milter.
# 
# At the next level, the <code>Milter</code> module (note the case difference)
# provides a Python friendly object oriented wrapper for the low level API.  To
# use the Milter module, an application registers a 'factory' to create an
# object for each connection from a MTA to sendmail.  These connection objects
# must provide methods corresponding to the libmilter callback events.
# 
# Each event method returns a code to tell sendmail whether to proceed with
# processing the message.  This is a big advantage of milters over other mail
# filtering systems.  Unwanted mail can be stopped in its tracks at the
# earliest possible point.
# 
# The <code>Milter.Base</code> class provides default implementations for
# event methods that do nothing, and also provides wrappers for the libmilter
# methods to mutate the message.  It automatically negotiates with MTA
# which protocol steps need to be processed by the milter, based on
# which callback methods are overridden.
#
# The <code>Milter.Milter</code> class provides an alternate default
# implementation that logs the main milter events, but otherwise does nothing.
# It is provided for compatibility.
# 
# The <code>mime</code> module provides a wrapper for the Python email package
# that fixes some bugs, and simplifies modifying selected parts of a MIME
# message.
