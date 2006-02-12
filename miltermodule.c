/* Copyright (C) 2001  James Niemira (niemira@colltech.com, urmane@urmane.org)
 * Portions Copyright (C) 2001,2002,2003,2004  Stuart Gathman (stuart@bmsi.com)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * milterContext object and thread interface contributed by
 * 	Stuart D. Gathman <stuart@bmsi.com>
 */

/* This is a Python extension to use Sendmail's libmilter functionality.  
   It is built using distutils.  To install it:

# python setup.py install 

   For additional options:

$ python setup.py help
  
   You may need to add additional libraries to setup.py.  For instance,
   Solaris2.6 requires 

     libraries=["milter","smutil","resolv"]

 * $Log$
 * Revision 1.9  2005/12/23 21:46:36  customdesigned
 * Compile on sendmail-8.12 (ifdef SMFIR_INSHEADER)
 *
 * Revision 1.8  2005/10/20 23:23:36  customdesigned
 * Include smfi_progress is SMFIR_PROGRESS defined
 *
 * Revision 1.7  2005/10/20 23:04:46  customdesigned
 * Add optional idx for position of added header.
 *
 * Revision 1.6  2005/07/15 22:18:17  customdesigned
 * Support callback exception policy
 *
 * Revision 1.5  2005/06/24 04:20:07  customdesigned
 * Report context allocation error.
 *
 * Revision 1.4  2005/06/24 04:12:43  customdesigned
 * Remove unused name argument to generic wrappers.
 *
 * Revision 1.3  2005/06/24 03:57:35  customdesigned
 * Handle close called before connect.
 *
 * Revision 1.2  2005/06/02 04:18:55  customdesigned
 * Update copyright notices after reading article on /.
 *
 * Revision 1.1.1.2  2005/05/31 18:09:06  customdesigned
 * Release 0.7.1
 *
 * Revision 2.31  2004/08/23 02:24:36  stuart
 * Support setbacklog
 *
 * Revision 2.30  2004/08/21 20:29:53  stuart
 * Support option of 11 lines max for mlreply.
 *
 * Revision 2.29  2004/08/21 04:14:29  stuart
 * mlreply support
 *
 * Revision 2.28  2004/08/21 02:45:21  stuart
 * Don't leak int constants if module unloaded.
 *
 * Revision 2.27  2004/04/06 03:19:59  stuart
 * Release 0.6.8
 *
 * Revision 2.26  2004/03/04 21:43:06  stuart
 * Fix memory leak by removing unused dynamic template buffer,
 * thanks again to Alexander Kourakos.
 *
 * Revision 2.25  2004/03/01 19:45:03  stuart
 * Release 0.6.5
 *
 * Revision 2.24  2004/03/01 18:56:50  stuart
 * Support progress reporting.
 *
 * Revision 2.23  2004/03/01 18:36:09  stuart
 * Plug memory leak.  Thanks to Alexander Kourakos.
 *
 * Revision 2.22  2003/11/02 03:01:46  stuart
 * Adjust SMTP error codes after careful reading of standard.
 *
 * Revision 2.21  2003/06/24 19:57:04  stuart
 * Allow removing a python milter callback by setting to None.
 *
 * Revision 2.20  2003/02/13 17:08:57  stuart
 * IPV6 support
 *
 * Revision 2.19  2003/02/13 16:58:29  stuart
 * Support passing None to setreply and chgheader.
 *
 * Revision 2.18  2002/12/11 16:44:06  stuart
 * Support QUARANTINE if supported by libmilter.
 *
 * Revision 2.17  2002/04/18 20:20:35  stuart
 * Fix for NULL hostaddr in connect callback from Jason Erickson.
 *
 * Revision 2.16  2001/09/26 13:29:09  stuart
 * sa_len not supported by linux.
 *
 * Revision 2.15  2001/09/25 17:28:40  stuart
 * Copyrights, documentation, release 0.3.1
 *
 * Revision 2.14  2001/09/25 00:36:57  stuart
 * Pass hostaddr to python code in format used by standard socket module.
 *
 * Revision 2.13  2001/09/24 23:44:55  stuart
 * Return old callback from setcallback functions.
 *
 * Revision 2.12  2001/09/24 20:02:30  stuart
 * Remove redundant setpriv
 *
 * Revision 2.11  2001/09/23 22:26:35  stuart
 * Update docs.  Streamline Milter.py
 * update testbms.py to reflect actual sendmail behaviour with multiple
 * messages per connection.
 *
 * Revision 2.10  2001/09/22 15:33:42  stuart
 * More doc comment updates.
 *
 * Revision 2.9  2001/09/22 14:52:27  stuart
 * Actually return retval in _generic_return.
 * Go over doc comments.
 *
 * Revision 2.8  2001/09/22 01:59:32  stuart
 * Prevent reentrant call of milter_main, which libmilter doesn't support.
 *
 * Revision 2.7  2001/09/22 01:47:37  stuart
 * Forgot to set milter interp.
 *
 * Revision 2.6  2001/09/22 01:23:53  stuart
 * Added proper threading after research in python docs.
 *
 * Revision 2.5  2001/09/21 20:08:51  stuart
 * Release 0.2.3
 *
 * Revision 2.4  2001/09/20 16:18:16  stuart
 * libmilter checks in_eom state, so we don't have to.
 *
 * Revision 2.3  2001/09/19 06:02:33  stuart
 * Make more stuff static.
 *
 * Revision 2.1  2001/09/19 04:24:13  stuart
 * Use extension type to track context in python.
 *
 * Revision 1.4  2001/09/18 18:48:28  stuart
 * clear private data reference in _clear_context
 *
 * Revision 1.3  2001/09/15  04:19:37  stuart
 * nasty off by 1 mem overwrite bugs in wrap_env
 * generic_set_callback
 *
 * Revision 1.2  2001/09/15  03:15:39  stuart
 * several bugs fixed, works smoothly
 *
 */

#ifndef MAX_ML_REPLY
#define MAX_ML_REPLY 32
#endif
#if MAX_ML_REPLY != 1 && MAX_ML_REPLY != 32 && MAX_ML_REPLY != 11
#error MAX_ML_REPLY must be 1 or 11 or 32
#endif
#define _FFR_MULTILINE (MAX_ML_REPLY > 1)

#include <pthread.h>
#include <netinet/in.h>
#include <Python.h>
#include <libmilter/mfapi.h>


/* See if we have IPv4 and/or IPv6 support in this OS and in
 * libmilter.  We need to make several macro tests because some OS's
 * may define some if IPv6 is only partially supported, and we may
 * have a sendmail without IPv4 (compiled for IPv6-only).
 */
#ifdef SMFIA_INET
#ifdef AF_INET
#define HAVE_IPV4_SUPPORT /* use this for #ifdef's later on */
#endif
#endif

#ifdef SMFIA_INET6
#ifdef AF_INET6
#ifdef IN6ADDR_ANY_INIT
#ifdef INET6_ADDRSTRLEN
#define HAVE_IPV6_SUPPORT /* use this for #ifdef's later on */
/* Now see if it supports the RFC-2553 socket's API spec.  Early
 * IPv6 "prototype" implementations existed before the RFC was
 * published.  Unfortunately I know of now good way to do this
 * other than with OS-specific tests.
 */
#ifdef linux
#define HAVE_IPV6_RFC2553
#include <arpa/inet.h>
#endif
#ifdef __HPUX
/* only HP-UX 11.1 or greater supports IPv6 */
#define HAVE_IPV6_RFC2553
#endif

#endif
#endif
#endif
#endif


/* Yes, these are static.  If you need multiple different callbacks, */
/* it's cleaner to use multiple filters, or convert to OO method calls. */
static PyObject *connect_callback = NULL;
static PyObject *helo_callback    = NULL;
static PyObject *envfrom_callback = NULL;
static PyObject *envrcpt_callback = NULL;
static PyObject *header_callback  = NULL;
static PyObject *eoh_callback     = NULL;
static PyObject *body_callback    = NULL;
static PyObject *eom_callback     = NULL;
static PyObject *abort_callback   = NULL;
static PyObject *close_callback   = NULL;

staticforward struct smfiDesc description; /* forward declaration */

static PyObject *MilterError;
/* The interpreter instance that called milter.main */
static PyInterpreterState *interp;

staticforward PyTypeObject milter_ContextType;

typedef struct {
  PyObject_HEAD
  SMFICTX *ctx;		/* libmilter thread state */
  PyObject *priv;	/* user python object */
  PyThreadState *t;	/* python thread state */
} milter_ContextObject;

/* Return a borrowed reference to the python Context.  Create a
   new Context if needed.  The new Python Context is owned by
   the SMFICTX. The python interpreter is locked on successful
   return, otherwise not. */
static milter_ContextObject *
_get_context(SMFICTX *ctx) {
  milter_ContextObject *self = smfi_getpriv(ctx);
  if (self) {
    /* Can't pass on exception since we are called from libmilter */
    if (self->ctx != ctx) return NULL;
    PyEval_AcquireThread(self->t);
  }
  else {
    PyThreadState *t = PyThreadState_New(interp);
    if (t == NULL) return NULL;
    PyEval_AcquireThread(t);	/* lock interp */
    self = PyObject_New(milter_ContextObject,&milter_ContextType);
    if (!self) {
      /* Report and clear exception since we are called from libmilter */
      if (PyErr_Occurred()) {
	PyErr_Print();
	PyErr_Clear();
      }
      PyThreadState_Clear(t);
      PyEval_ReleaseThread(t);
      PyThreadState_Delete(t);
      return NULL;
    }
    self->t = t;
    self->ctx = ctx;
    Py_INCREF(Py_None);
    self->priv = Py_None;	/* User Python object */
    smfi_setpriv(ctx, self);
  }
  return self;
}

/* Find the SMFICTX from a Python Context. The interpreter must be locked. */
static SMFICTX *
_find_context(PyObject *c) {
  SMFICTX *ctx = NULL;
  if (c->ob_type == &milter_ContextType) {
    milter_ContextObject *self = (milter_ContextObject *)c;
    ctx = self->ctx;
    if (ctx != NULL && smfi_getpriv(ctx) != self)
      ctx = NULL;
  }
  if (ctx == NULL)
    PyErr_SetString(MilterError, "bad context");
  return ctx;
}

static void
milter_Context_dealloc(PyObject *s) {
  milter_ContextObject *self = (milter_ContextObject *)s;
  SMFICTX *ctx = self->ctx;
  if (ctx) {
    /* Should never happen.  If libmilter closes SMFICTX first, then
      ctx will be 0.  Otherwise, SMFICTX will still hold a reference
      to the ContextObject.  But if it does, make sure SMFICTX can't
      reach us anymore. */
    smfi_setpriv(ctx,0);
  }
  Py_DECREF(self->priv);
  PyObject_DEL(self);
}

/* Throw an exception if an smfi call failed, otherwise return PyNone. */
static PyObject *
_generic_return(int val, char *errstr) {
  if (val == MI_SUCCESS) {
    Py_INCREF(Py_None);
    return Py_None;
  } else {
    PyErr_SetString(MilterError, errstr);
    return NULL;
  }
}

static PyObject *
_thread_return(PyThreadState *t,int val,char *errstr) {
  PyEval_RestoreThread(t);	/* lock interpreter again */
  return _generic_return(val,errstr);
}

static char milter_set_flags__doc__[] =
"set_flags(int) -> None\n\
Set flags for filter capabilities; OR of one or more of:\n\
ADDHDRS - filter may add headers\n\
CHGBODY - filter may replace body\n\
ADDRCPT - filter may add recipients\n\
DELRCPT - filter may delete recipients\n\
CHGHDRS - filter may change/delete headers";

static PyObject *
milter_set_flags(PyObject *self, PyObject *args) {
  if (!PyArg_ParseTuple(args, "i:set_flags", &description.xxfi_flags))
    return NULL;
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
generic_set_callback(PyObject *args,char *t,PyObject **cb) {
  PyObject *callback;
  PyObject *oldval;

  if (!PyArg_ParseTuple(args, t, &callback)) return NULL;
  if (callback == Py_None)
    callback = 0;
  else {
    if (!PyCallable_Check(callback)) {
      PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    Py_INCREF(callback);
  }
  oldval = *cb;
  *cb = callback;
  if (oldval)
    return oldval;
  Py_INCREF(Py_None);
  return Py_None;
}

static char milter_set_connect_callback__doc__[] =
"set_connect_callback(Function) -> None\n\
Sets the Python function invoked when a connection is made to sendmail.\n\
Function takes args (ctx, hostname, integer, hostaddr) -> int\n\
ctx -> milterContext for connection, also on remaining callbacks\n\
hostname -> String - the connecting remote hostname\n\
integer -> int - the protocol family, one of socket.AF_* values\n\
hostaddr -> ? - the connecting host address in format used by socket:\n\
      for unix -> pathname - like '/tmp/sockets/s24823'\n\
      for inet -> (ipaddress, port) - like ('10.1.2.3',3701)\n\
      for inet6 -> (ip6address, port, flowlabel, scope) - like ('fec0:0:0:2::4e', 3701, 0, 5)\n\
\n\
The return value on this and remaining callbacks should be one of:\n\
CONTINUE - continue processing\n\
REJECT - sendmail refuses to accept any more data for message\n\
ACCEPT - sendmail accepts the message\n\
DISCARD - sendmail accepts the message and discards it\n\
TEMPFAIL - milter problem, sendmail will try again later\n\
\n\
A python exception encountered in a callback will return TEMPFAIL.";

static PyObject *
milter_set_connect_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args,
    "O:set_connect_callback", &connect_callback);
}

static char milter_set_helo_callback__doc__[] =
"set_helo_callback(Function) -> None\n\
Sets the Python function invoked upon SMTP HELO.\n\
Function takes args (ctx, hostname) -> int\n\
hostname -> String - the name given with the helo command.";

static PyObject *
milter_set_helo_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_helo_callback", &helo_callback);
}

static char milter_set_envfrom_callback__doc__[] =
"set_envfrom_callback(Function) -> None\n\
Sets the Python function invoked on envelope from.\n\
Function takes args (ctx, from, *str) -> int\n\
from -> sender\n\
str -> Tuple of additional parameters defined by ESMTP.";

static PyObject *
milter_set_envfrom_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_envfrom_callback",
  	&envfrom_callback);
}

static char milter_set_envrcpt_callback__doc__[] =
"set_envrcpt_callback(Function) -> None\n\
Sets the Python function invoked on each envelope recipient.\n\
Function takes args (ctx, rcpt, *str) -> int\n\
tcpt -> string - recipient\n\
str -> Tuple of additional parameters defined by ESMTP.";

static PyObject *
milter_set_envrcpt_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_envrcpt_callback",
  	&envrcpt_callback);
}

static char milter_set_header_callback__doc__[] =
"set_header_callback(Function) -> None\n\
Sets the Python function invoked on each message header.\n\
Function takes args (ctx, field, value) ->int\n\
field -> String - the header\n\
value -> String - the header's value";

static PyObject *
milter_set_header_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_header_callback",
  	&header_callback);
}

static char milter_set_eoh_callback__doc__[] =
"set_eoh_callback(Function) -> None\n\
Sets the Python function invoked at end of header.\n\
Function takes args (ctx) -> int";

static PyObject *
milter_set_eoh_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_eoh_callback", &eoh_callback);
}

static char milter_set_body_callback__doc__[] =
"set_body_callback(Function) -> None\n\
Sets the Python function invoked for each body chunk. There may\n\
be multiple body chunks passed to the filter. End-of-lines are\n\
represented as received from SMTP (normally Carriage-Return/Line-Feed).\n\
Function takes args (ctx, chunk) -> int\n\
chunk -> String - body data";

static PyObject *
milter_set_body_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_body_callback", &body_callback);
}

static char milter_set_eom_callback__doc__[] =
"set_eom_callback(Function) -> None\n\
Sets the Python function invoked at end of message.\n\
This routine is the only place where special operations\n\
such as modifying the message header, body, or\n\
envelope can be used.\n\
Function takes args (ctx) -> int";

static PyObject *
milter_set_eom_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_eom_callback", &eom_callback);
}

static char milter_set_abort_callback__doc__[] =
"set_abort_callback(Function) -> None\n\
Sets the Python function invoked if message is aborted\n\
outside of the control of the filter, for example,\n\
if the SMTP sender issues an RSET command. If the \n\
abort callback is called, the eom callback will not be\n\
called and vice versa.\n\
Function takes args (ctx) -> int";

static PyObject *
milter_set_abort_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_abort_callback", &abort_callback);
}

static char milter_set_close_callback__doc__[] =
"set_close_callback(Function) -> None\n\
Sets the Python function invoked at end of the connection.  This\n\
is called on close even if the previous mail transaction was aborted.\n\
Function takes args (ctx) -> int";

static PyObject *
milter_set_close_callback(PyObject *self, PyObject *args) {
  return generic_set_callback(args, "O:set_close_callback", &close_callback);
}

static int exception_policy = SMFIS_TEMPFAIL;

static char milter_set_exception_policy__doc__[] =
"set_exception_policy(i) -> None\n\
Sets the policy for untrapped Python exceptions during a callback.\n\
Must be one of TEMPFAIL,REJECT,CONTINUE";

static PyObject *
milter_set_exception_policy(PyObject *self, PyObject *args) {
  int i;
  if (!PyArg_ParseTuple(args, "i:set_exception_policy", &i))
    return NULL;
  switch (i) {
  case SMFIS_REJECT: case SMFIS_TEMPFAIL: case SMFIS_CONTINUE:
    exception_policy = i;
    Py_INCREF(Py_None);
    return Py_None;
  }
  PyErr_SetString(MilterError,"invalid exception policy");
  return NULL;
}

static void
_release_thread(PyThreadState *t) {
  if (t != NULL)
    PyEval_ReleaseThread(t);
}

/** Report and clear any python exception before returning to libmilter. 
  The interpreter is locked when we are called, and we unlock it.  */
static int _report_exception(milter_ContextObject *self) {
  if (PyErr_Occurred()) {
    PyErr_Print();
    PyErr_Clear();	/* must clear since not returning to python */
    _release_thread(self->t);
    switch (exception_policy) {
      case SMFIS_REJECT:
	smfi_setreply(self->ctx, "554", "5.3.0", "Filter failure");
	return SMFIS_REJECT;
      case SMFIS_TEMPFAIL:
	smfi_setreply(self->ctx, "451", "4.3.0", "Filter failure");
	return SMFIS_TEMPFAIL;
    }
    return SMFIS_CONTINUE;
  }
  _release_thread(self->t);
  return SMFIS_CONTINUE;
}

/* Return to libmilter.  The ctx must have been initialized or
  checked by a successfull call to _get_context(), thereby locking
  the interpreter. */
static int
_generic_wrapper(milter_ContextObject *self, PyObject *cb, PyObject *arglist) {
  PyObject *result;
  int retval;

  if (arglist == NULL) return _report_exception(self);
  result = PyEval_CallObject(cb, arglist);
  Py_DECREF(arglist);
  if (result == NULL) return _report_exception(self);
  retval = PyInt_AsLong(result);
  Py_DECREF(result);
  if (PyErr_Occurred()) return _report_exception(self);
  _release_thread(self->t);
  return retval;
}

/* Create a string object representing an IP address.
   This is always a string of the form 'dd.dd.dd.dd' (with variable
   size numbers). Copied from standard socket module. */

static PyObject *
makeipaddr(struct sockaddr_in *addr) {
	long x = ntohl(addr->sin_addr.s_addr);
	char buf[100];
	sprintf(buf, "%d.%d.%d.%d",
		(int) (x>>24) & 0xff, (int) (x>>16) & 0xff,
		(int) (x>> 8) & 0xff, (int) (x>> 0) & 0xff);
	return PyString_FromString(buf);
}

#ifdef HAVE_IPV6_SUPPORT
static PyObject *
makeip6addr(struct sockaddr_in6 *addr) {
	char buf[100]; /* must be at least INET6_ADDRSTRLEN + 1 */
	const char *s = inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof buf);
	if (s) return PyString_FromString(s);
	return PyString_FromString("inet6:unknown");
}
#endif

/* These are wrapper functions to call the Python callbacks for each event */
static int
milter_wrap_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
  PyObject *arglist;
  milter_ContextObject *c;
  if (connect_callback == NULL) return SMFIS_CONTINUE;
  c = _get_context(ctx);
  if (!c) return SMFIS_TEMPFAIL;
  if (hostaddr != NULL) {
    switch (hostaddr->sa_family) {
    case AF_INET:
      { struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
        PyObject *ipaddr_obj = makeipaddr(sa);
        arglist = Py_BuildValue("(Osh(Oi))", c, hostname, hostaddr->sa_family,
                            ipaddr_obj, ntohs(sa->sin_port));
        Py_DECREF(ipaddr_obj);
      }
      break;
    case AF_UNIX:
      arglist = Py_BuildValue("(Oshs)", c, hostname, hostaddr->sa_family,
                            hostaddr->sa_data);
      break;
#ifdef HAVE_IPV6_SUPPORT
    case AF_INET6:
      { struct sockaddr_in6 *sa = (struct sockaddr_in6 *)hostaddr;
        PyObject *ip6addr_obj = makeip6addr(sa);
        long scope_id = 0;
#ifdef HAVE_IPV6_RFC2553
	scope_id = ntohl(sa->sin6_scope_id);
#endif
        arglist = Py_BuildValue("(Osh(Oiii))", c, hostname, hostaddr->sa_family,
				ip6addr_obj,
				ntohs(sa->sin6_port),
				ntohl(sa->sin6_flowinfo),
				scope_id);
        Py_DECREF(ip6addr_obj);
      }
      break;
#endif
    default:
      arglist = Py_BuildValue("(OshO)", c, hostname, hostaddr->sa_family,
                            Py_None);
    }
  }
  else
    arglist = Py_BuildValue("(OshO)", c, hostname, 0, Py_None);
  return _generic_wrapper(c, connect_callback, arglist);
}

static int
milter_wrap_helo(SMFICTX *ctx, char *helohost) {
  PyObject *arglist;
  milter_ContextObject *c;

  if (helo_callback == NULL) return SMFIS_CONTINUE;
  c = _get_context(ctx);
  if (!c) return SMFIS_TEMPFAIL;
  arglist = Py_BuildValue("(Os)", c, helohost);
  return _generic_wrapper(c, helo_callback, arglist);
}

static int
generic_env_wrapper(SMFICTX *ctx, PyObject*cb, char **argv) {
   PyObject *arglist;
   milter_ContextObject *self;
   int count = 0;
   int i;
   char **p = argv;

   if (cb == NULL) return SMFIS_CONTINUE; 

   self = _get_context(ctx);
   if (!self) return SMFIS_TEMPFAIL;

   /* Count how many strings we've been passed. */
   while (*p++ != NULL) count++;
   /* how to build the value in steps?  Cheat by copying from */
   /* Python/modsupport.c do_mktuple() and do_mkvalue() */
   if ((arglist = PyTuple_New(count+1)) == NULL)
     return _report_exception(self);
   /* Add in the context first */
   Py_INCREF(self);	/* PyTuple_SetItem takes over reference */
   PyTuple_SetItem(arglist, 0, (PyObject *)self);
   /* Now do all the strings */
   for (i=0;i<count;i++) {
     /* There's some error checking performed in do_mkvalue() for a string */
     /* that's not currently done here - it probably should be */
     PyObject *o = PyString_FromStringAndSize(argv[i], strlen(argv[i]));
     if (o == NULL) {	/* out of memory */
       Py_DECREF(arglist);
       return _report_exception(self);
     }
     PyTuple_SetItem(arglist, i + 1, o);
   }
   return _generic_wrapper(self, cb, arglist);
}

static int
milter_wrap_envfrom(SMFICTX *ctx, char **argv) {
  return generic_env_wrapper(ctx,envfrom_callback,argv);
}

static int
milter_wrap_envrcpt(SMFICTX *ctx, char **argv) {
  return generic_env_wrapper(ctx,envrcpt_callback,argv);
}    
  
static int
milter_wrap_header(SMFICTX *ctx, char *headerf, char *headerv) {
   PyObject *arglist;
   milter_ContextObject *c;

   if (header_callback == NULL) return SMFIS_CONTINUE;
   c = _get_context(ctx);
   if (!c) return SMFIS_TEMPFAIL;
   arglist = Py_BuildValue("(Oss)", c, headerf, headerv);
   return _generic_wrapper(c, header_callback, arglist);
}

static int
generic_noarg_wrapper(SMFICTX *ctx,PyObject *cb) {
   PyObject *arglist;
   milter_ContextObject *c;
   if (cb == NULL) return SMFIS_CONTINUE;
   c = _get_context(ctx);
   if (!c) return SMFIS_TEMPFAIL;
   arglist = Py_BuildValue("(O)", c);
   return _generic_wrapper(c, cb, arglist);
}

static int
milter_wrap_eoh(SMFICTX *ctx) {
  return generic_noarg_wrapper(ctx,eoh_callback);
}   

static int
milter_wrap_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen) {
   PyObject *arglist;
   milter_ContextObject *c;

   if (body_callback == NULL) return SMFIS_CONTINUE;
   c = _get_context(ctx);
   if (!c) return SMFIS_TEMPFAIL;
   /* Unclear whether this should be s#, z#, or t# */
   arglist = Py_BuildValue("(Os#)", c, bodyp, bodylen);
   return _generic_wrapper(c, body_callback, arglist);
}

static int
milter_wrap_eom(SMFICTX *ctx) {
  return generic_noarg_wrapper(ctx,eom_callback);
}

static int
milter_wrap_abort(SMFICTX *ctx) {
  /* libmilter still calls close after abort */
  return generic_noarg_wrapper(ctx,abort_callback);
}

static int
milter_wrap_close(SMFICTX *ctx) {
  /* xxfi_close can be called out of order - even before connect.  
   * There may not yet be a private context pointer.  To avoid
   * creating a ThreadContext and allocating a milter context only
   * to destroy them, and to avoid invoking the python close_callback when
   * connect has never been called, we don't use generic_noarg_wrapper here. */
  PyObject *cb = close_callback;
  milter_ContextObject *self = smfi_getpriv(ctx);
  int r = SMFIS_CONTINUE;
  if (self != NULL) {
    PyThreadState *t = self->t;
    PyEval_AcquireThread(t);
    self->t = 0;
    if (cb != NULL && self->ctx == ctx) {
      PyObject *arglist = Py_BuildValue("(O)", self);
      /* Call python close callback, but do not ReleaseThread, because
       * self->t is NULL */
      r = _generic_wrapper(self, cb, arglist);
    }
    self->ctx = 0;
    smfi_setpriv(ctx,0);
    Py_DECREF(self);
    PyThreadState_Clear(t);
    PyEval_ReleaseThread(t);
    PyThreadState_Delete(t);
  }
  return r;
}

static char milter_register__doc__[] =
"register(name) -> None\n\
Registers the milter name with current callbacks, and flags.\n\
Required before main() is called.";

static PyObject *
milter_register(PyObject *self, PyObject *args) {
   if (!PyArg_ParseTuple(args, "s:register", &description.xxfi_name))
      return NULL;
   return _generic_return(smfi_register(description), "cannot register");
}

static char milter_main__doc__[] =
"main() -> None\n\
Main milter routine.  Set any callbacks, and flags desired, then call\n\
setconn(), then call register(name), and finally call main().";

static PyObject *
milter_main(PyObject *self, PyObject *args) {
  PyThreadState *_main;
  PyObject *o;
  if (!PyArg_ParseTuple(args, ":main")) return NULL;
  if (interp != NULL) {
    PyErr_SetString(MilterError,"milter module in use");
    return NULL;
  }
  /* libmilter requires thread support */
  PyEval_InitThreads();	
  /* let other threads run while in smfi_main() */
  interp = PyThreadState_Get()->interp;
  _main = PyEval_SaveThread();	/* must be done before smfi_main() */
  o = _thread_return(_main,smfi_main(), "cannot run main");
  interp = NULL;
  return o;
}

static char milter_setdbg__doc__[] =
"setdbg(int) -> None\n\
Sets debug level in sendmail/libmilter source.  Dubious usefulness.";

static PyObject *
milter_setdbg(PyObject *self, PyObject *args) {
  int val;
  if (!PyArg_ParseTuple(args, "i:setdbg", &val)) return NULL;
  return _generic_return(smfi_setdbg(val), "cannot set debug value");
}

static char milter_setbacklog__doc__[] =
"setbacklog(int) -> None\n\
Set the TCP connection queue size for the milter socket.";

static PyObject *
milter_setbacklog(PyObject *self, PyObject *args) {
   int val;

   if (!PyArg_ParseTuple(args, "i:setbacklog", &val)) return NULL;
   return _generic_return(smfi_setbacklog(val), "cannot set backlog");
}

static char milter_settimeout__doc__[] =
"settimeout(int) -> None\n\
Set the time (in seconds) that sendmail will wait before\n\
considering this filter dead.";

static PyObject *
milter_settimeout(PyObject *self, PyObject *args) {
   int val;

   if (!PyArg_ParseTuple(args, "i:settimeout", &val)) return NULL;
   return _generic_return(smfi_settimeout(val), "cannot set timeout");
}

static char milter_setconn__doc__[] =
"setconn(filename) -> None\n\
Sets the pathname to the unix, inet, or inet6 socket that\n\
sendmail will use to communicate with this filter.  By default,\n\
a unix domain socket is used.  It must not exist,\n\
and sendmail will throw warnings if, eg, the file is under a\n\
group or world writable directory.  This call is \n\
mandatory, and is invoked before register() and main().\n\
  setconn('unix:/var/run/pythonfilter')\n\
  setconn('inet:8800') # listen on ANY interface\n\
  setconn('inet:7871@publichost')\n\
  setconn('inet6:8020')";

static PyObject *
milter_setconn(PyObject *self, PyObject *args) {
   char *str;
   if (!PyArg_ParseTuple(args, "s:setconn", &str)) return NULL;
   return _generic_return(smfi_setconn(str), "cannot set connection");
}

static char milter_stop__doc__[] =
"stop() -> None\n\
This function appears to be a controlled method to tell sendmail to\n\
stop using this filter.  It will close the socket.";

static PyObject *
milter_stop(PyObject *self, PyObject *args) {
  PyThreadState *t;
  if (!PyArg_ParseTuple(args, ":stop")) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_stop(), "cannot stop");
}

static char milter_getsymval__doc__[] =
"getsymval(String) -> String\n\
Returns a symbol's value.  Context-dependent, and unclear from the dox.";

static PyObject *
milter_getsymval(PyObject *self, PyObject *args) {
  char *str;
  SMFICTX *ctx;
  
  if (!PyArg_ParseTuple(args, "s:getsymval", &str)) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  return Py_BuildValue("s", smfi_getsymval(ctx, str));
}

static char milter_setreply__doc__[] =
"setreply(rcode, xcode, message) -> None\n\
Sets the specific reply code to be used in response\n\
to the active command.\n\
rcode - The three-digit (RFC 821) SMTP reply code to be returned\n\
xcode - The extended (RFC 2034) reply code\n\
message - The text part of the SMTP reply\n\
These should all be strings.";

static PyObject *
milter_setreply(PyObject *self, PyObject *args) {
  char *rcode;
  char *xcode;
  char *message[MAX_ML_REPLY];
  char fmt[MAX_ML_REPLY + 16];
  SMFICTX *ctx;
  int i;
  strcpy(fmt,"sz|");
  for (i = 0; i < MAX_ML_REPLY; ++i) {
    message[i] = 0;
    fmt[i+3] = 's';
  }
  strcpy(fmt+i+3,":setreply");
  if (!PyArg_ParseTuple(args, fmt,
	&rcode, &xcode, message
#if MAX_ML_REPLY > 1
	,message+1,message+2,message+3,message+4,message+5,message+6,
	message+7,message+8,message+9,message+10
#if MAX_ML_REPLY > 11
	,message+11,message+12,message+13,message+14,message+15,
	message+16,message+17,message+18,message+19,message+20,
	message+21,message+22,message+23,message+24,message+25,
	message+26,message+27,message+28,message+29,message+30,
	message+31
#endif
#endif
  ))
    return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
#if MAX_ML_REPLY > 1
  /*
   * C varargs might be convenient for some things, but they sure are a pain
   * when the number of args is not known at compile time.
   */
  if (message[0] && message[1])
    return _generic_return(smfi_setmlreply(ctx, rcode, xcode,
	  message[0],
	  message[1],message[2],message[3],message[4],message[5],
	  message[6],message[7],message[8],message[9],message[10],
#if MAX_ML_REPLY > 11
	  message[11],message[12],message[13],message[14],message[15],
	  message[16],message[17],message[18],message[19],message[20],
	  message[21],message[22],message[23],message[24],message[25],
	  message[26],message[27],message[28],message[29],message[30],
	  message[31],
#endif
	  (char *)0
    ), "cannot set reply");
#endif
  return _generic_return(smfi_setreply(ctx, rcode, xcode, message[0]),
			 "cannot set reply");
}

static char milter_addheader__doc__[] =
"addheader(field, value, idx=-1) -> None\n\
Add a header to the message. This header is not passed to other\n\
filters. It is not checked for standards compliance;\n\
the mail filter must ensure that no protocols are violated\n\
as a result of adding this header.\n\
field - header field name\n\
value - header field value\n\
idx - optional position in internal header list to insert new header\n\
Both are strings.  This function can only be called from the EOM callback.";

static PyObject *
milter_addheader(PyObject *self, PyObject *args) {
  char *headerf;
  char *headerv;
  int idx = -1;
  SMFICTX *ctx;
  PyThreadState *t;

  if (!PyArg_ParseTuple(args, "ss|i:addheader", &headerf, &headerv, &idx))
    return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
#ifdef SMFIR_INSHEADER
  return _thread_return(t, (idx < 0) ? smfi_addheader(ctx, headerf, headerv) :
      smfi_insheader(ctx, idx, headerf, headerv), "cannot add header");
#else
  if (idx < 0)
    return _thread_return(t, smfi_addheader(ctx, headerf, headerv),
	"cannot add header");
  PyErr_SetString(MilterError, "insheader not supported");
  return NULL;
#endif
}

static char milter_chgheader__doc__[] =
"chgheader(field, int, value) -> None\n\
Change/delete a header in the message. \n\
It is not checked for standards compliance; the mail filter\n\
must ensure that no protocols are violated as a result of adding this header.\n\
field - header field name\n\
int - the Nth occurence of this header\n\
value - header field value\n\
field and value are strings.\n\
This function can only be called from the EOM callback.";

static PyObject *
milter_chgheader(PyObject *self, PyObject *args) {
  char *headerf;
  int index;
  char *headerv;
  SMFICTX *ctx;
  PyThreadState *t;
  
  if (!PyArg_ParseTuple(args, "siz:chgheader", &headerf, &index, &headerv))
    return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_chgheader(ctx, headerf, index, headerv),
			 "cannot change header");
}

static char milter_addrcpt__doc__[] =
"addrcpt(string) -> None\n\
Add a recipient to the envelope.  It must be in the same format\n\
as is passed to the envrcpt callback in the first tuple element.\n\
This function can only be called from the EOM callback.";

static PyObject *
milter_addrcpt(PyObject *self, PyObject *args) {
  char *rcpt;
  SMFICTX *ctx;
  PyThreadState *t;
  
  if (!PyArg_ParseTuple(args, "s:addrcpt", &rcpt)) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_addrcpt(ctx, rcpt), "cannot add recipient");
}

static char milter_delrcpt__doc__[] =
"delrcpt(string) -> None\n\
Delete a recipient from the envelope.\n\
This function can only be called from the EOM callback.";

static PyObject *
milter_delrcpt(PyObject *self, PyObject *args) {
  char *rcpt;
  SMFICTX *ctx;
  PyThreadState *t;

  if (!PyArg_ParseTuple(args, "s:delrcpt", &rcpt)) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_delrcpt(ctx, rcpt),
			 "cannot delete recipient");
}

static char milter_replacebody__doc__[] =
"replacebody(string) -> None\n\
Replace the body of the message. This routine may be called multiple\n\
times if the body is longer than convenient to send in one call. End of\n\
line should be represented as Carriage-Return/Line Feed.  This function\n\
can only be called from the EOM callback.";

static PyObject *
milter_replacebody(PyObject *self, PyObject *args) {
  char *bodyp;
  int bodylen;
  SMFICTX *ctx;
  PyThreadState *t;
  
  if (!PyArg_ParseTuple(args, "s#", &bodyp, &bodylen)) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_replacebody(ctx, bodyp, bodylen),
			 "cannot replace message body");
}

static char milter_setpriv__doc__[] =
"setpriv(object) -> object\n\
Associates any Python object with this context, and returns\n\
the old value or None.  Use this to\n\
provide thread-safe storage for data instead of using global variables\n\
for things like filenames, etc.  This function stores only one object\n\
per context, but that object can in turn store many others.";

static PyObject *
milter_setpriv(PyObject *self, PyObject *args) {
  PyObject *o;
  PyObject *old;
  milter_ContextObject *s = (milter_ContextObject *)self;
  
  if (!PyArg_ParseTuple(args, "O:setpriv", &o)) return NULL;
  /* PyArg_ParseTuple's O format does not increase the reference count on
     the target.  Since we're going to save it and almost certainly assign
     to another object later, we incref it here, and only decref it in
     the dealloc method. */
  Py_INCREF(o);
  old = s->priv;
  s->priv = o;
  /* We return the old value.  The caller will DECREF it if not used. */
  return old;
}

static char milter_getpriv__doc__[] =
"getpriv() -> None\n\
Returns the Python object associated with the current context (if any).\n\
Use this in conjunction with setpriv to keep track of data in a thread-safe\n\
manner.";

static PyObject *
milter_getpriv(PyObject *self, PyObject *args) {
  PyObject *o;
  milter_ContextObject *s = (milter_ContextObject *)self;
  
  if (!PyArg_ParseTuple(args, ":getpriv")) return NULL;
  o = s->priv;
  Py_INCREF(o);
  return o;
}

#ifdef SMFIF_QUARANTINE
static char milter_quarantine__doc__[] =
"quarantine(string) -> None\n\
Place the message in quarantine.  A string with a description of the reason\n\
is the only argument.";

static PyObject *
milter_quarantine(PyObject *self, PyObject *args) {
  char *reason;
  SMFICTX *ctx;
  PyThreadState *t;

  if (!PyArg_ParseTuple(args, "s:quarantine", &reason)) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_quarantine(ctx, reason),
			 "cannot quarantine message");
}
#endif

#ifdef SMFIR_PROGRESS
static char milter_progress__doc__[] =
"progress() -> None\n\
Notify the MTA that we are working on a message so it will reset timeouts.";

static PyObject *
milter_progress(PyObject *self, PyObject *args) {
  SMFICTX *ctx;
  PyThreadState *t;

  if (!PyArg_ParseTuple(args, ":progress")) return NULL;
  ctx = _find_context(self);
  if (ctx == NULL) return NULL;
  t = PyEval_SaveThread();
  return _thread_return(t,smfi_progress(ctx), "cannot notify progress");
}
#endif

static PyMethodDef context_methods[] = {
  { "getsymval",   milter_getsymval,   METH_VARARGS, milter_getsymval__doc__},
  { "setreply",    milter_setreply,    METH_VARARGS, milter_setreply__doc__},
  { "addheader",   milter_addheader,   METH_VARARGS, milter_addheader__doc__},
  { "chgheader",   milter_chgheader,   METH_VARARGS, milter_chgheader__doc__},
  { "addrcpt",     milter_addrcpt,     METH_VARARGS, milter_addrcpt__doc__},
  { "delrcpt",     milter_delrcpt,     METH_VARARGS, milter_delrcpt__doc__},
  { "replacebody", milter_replacebody, METH_VARARGS, milter_replacebody__doc__},
  { "setpriv",     milter_setpriv,     METH_VARARGS, milter_setpriv__doc__},
  { "getpriv",     milter_getpriv,     METH_VARARGS, milter_getpriv__doc__},
#ifdef SMFIF_QUARANTINE
  { "quarantine",  milter_quarantine,  METH_VARARGS, milter_quarantine__doc__},
#endif
#ifdef SMFIR_PROGRESS
  { "progress",  milter_progress,  METH_VARARGS, milter_progress__doc__},
#endif
  { NULL, NULL }
};

static PyObject *
milter_Context_getattr(PyObject *self, char *name) {
  return Py_FindMethod(context_methods, self, name);
}

static struct smfiDesc description = {  /* Set some reasonable defaults */
  "pythonfilter",
  SMFI_VERSION,
  SMFI_CURR_ACTS,
  milter_wrap_connect,
  milter_wrap_helo,
  milter_wrap_envfrom,
  milter_wrap_envrcpt,
  milter_wrap_header,
  milter_wrap_eoh,
  milter_wrap_body,
  milter_wrap_eom,
  milter_wrap_abort,
  milter_wrap_close
};

static PyMethodDef milter_methods[] = {
   { "set_flags",            milter_set_flags,            METH_VARARGS, milter_set_flags__doc__},
   { "set_connect_callback", milter_set_connect_callback, METH_VARARGS, milter_set_connect_callback__doc__},
   { "set_helo_callback",    milter_set_helo_callback,    METH_VARARGS, milter_set_helo_callback__doc__},
   { "set_envfrom_callback", milter_set_envfrom_callback, METH_VARARGS, milter_set_envfrom_callback__doc__},
   { "set_envrcpt_callback", milter_set_envrcpt_callback, METH_VARARGS, milter_set_envrcpt_callback__doc__},
   { "set_header_callback",  milter_set_header_callback,  METH_VARARGS, milter_set_header_callback__doc__},
   { "set_eoh_callback",     milter_set_eoh_callback,     METH_VARARGS, milter_set_eoh_callback__doc__},
   { "set_body_callback",    milter_set_body_callback,    METH_VARARGS, milter_set_body_callback__doc__},
   { "set_eom_callback",     milter_set_eom_callback,     METH_VARARGS, milter_set_eom_callback__doc__},
   { "set_abort_callback",   milter_set_abort_callback,   METH_VARARGS, milter_set_abort_callback__doc__},
   { "set_close_callback",   milter_set_close_callback,   METH_VARARGS, milter_set_close_callback__doc__},
   { "set_exception_policy",   milter_set_exception_policy,METH_VARARGS, milter_set_exception_policy__doc__},
   { "register",             milter_register,             METH_VARARGS, milter_register__doc__},
   { "register",             milter_register,             METH_VARARGS, milter_register__doc__},
   { "main",                 milter_main,                 METH_VARARGS, milter_main__doc__},
   { "setdbg",               milter_setdbg,               METH_VARARGS, milter_setdbg__doc__},
   { "settimeout",           milter_settimeout,           METH_VARARGS, milter_settimeout__doc__},
   { "setbacklog",           milter_setbacklog,           METH_VARARGS, milter_setbacklog__doc__},
   { "setconn",              milter_setconn,              METH_VARARGS, milter_setconn__doc__},
   { "stop",                 milter_stop,                 METH_VARARGS, milter_stop__doc__},
   { NULL, NULL }
};

static PyTypeObject milter_ContextType = {
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "milterContext",
  sizeof(milter_ContextObject),
  0,
        milter_Context_dealloc,            /* tp_dealloc */
        0,               /* tp_print */
        milter_Context_getattr,           /* tp_getattr */
        0,			/* tp_setattr */
        0,                                      /* tp_compare */
        0,                 /* tp_repr */
        0,                     /* tp_as_number */
        0,                                      /* tp_as_sequence */
        0,                                      /* tp_as_mapping */
        0,                 /* tp_hash */
        0,                                      /* tp_call */
        0,                  /* tp_str */
        0,                                      /* tp_getattro */
        0,                                      /* tp_setattro */
        0,                                      /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                     /* tp_flags */
};

static char milter_documentation[] =
"This module interfaces with Sendmail's libmilter functionality,\n\
allowing one to write email filters directly in Python.\n\
Libmilter is currently marked FFR, and needs to be explicitly installed.\n\
See <sendmailsource>/libmilter/README for details on setting it up.\n";

static void setitem(PyObject *d,const char *name,long val) {
  PyObject *v = PyInt_FromLong(val);
  PyDict_SetItemString(d,name,v);
  Py_DECREF(v);
}

void
initmilter(void) {
   PyObject *m, *d;

   m = Py_InitModule4("milter", milter_methods, milter_documentation,
		      (PyObject*)NULL, PYTHON_API_VERSION);
   d = PyModule_GetDict(m);
   MilterError = PyErr_NewException("milter.error", NULL, NULL);
   PyDict_SetItemString(d,"error", MilterError);
   setitem(d,"SUCCESS",  MI_SUCCESS);
   setitem(d,"FAILURE",  MI_FAILURE);
   setitem(d,"VERSION",  SMFI_VERSION);
   setitem(d,"ADDHDRS",  SMFIF_ADDHDRS);
   setitem(d,"CHGBODY",  SMFIF_CHGBODY);
   setitem(d,"MODBODY",  SMFIF_MODBODY);
   setitem(d,"ADDRCPT",  SMFIF_ADDRCPT);
   setitem(d,"DELRCPT",  SMFIF_DELRCPT);
   setitem(d,"CHGHDRS",  SMFIF_CHGHDRS);
   setitem(d,"V1_ACTS",  SMFI_V1_ACTS);
   setitem(d,"V2_ACTS",  SMFI_V2_ACTS);
   setitem(d,"CURR_ACTS",  SMFI_CURR_ACTS);
#ifdef SMFIF_QUARANTINE
   setitem(d,"QUARANTINE",SMFIF_QUARANTINE);
#endif
   setitem(d,"CONTINUE",  SMFIS_CONTINUE);
   setitem(d,"REJECT",  SMFIS_REJECT);
   setitem(d,"DISCARD",  SMFIS_DISCARD);
   setitem(d,"ACCEPT",  SMFIS_ACCEPT);
   setitem(d,"TEMPFAIL",  SMFIS_TEMPFAIL);
}
