%if 0%{?rhel} == 7
%define pythonbase python34
%else
%define pythonbase python3
%endif
%define __python python3

%define libdir %{_libdir}/pymilter
%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}

Summary: Python interface to sendmail milter API
Name: %{pythonbase}-pymilter
Version: 1.0.2
Release: 1%{dist}
Source: https://github.com/sdgathman/pymilter/archive/pymilter-%{version}.tar.gz
Source1: pymilter.te
# Patch miltermodule to python3
# FIXME: replace with reverse patch at some point (make py3 the default)
Patch: milter.patch
License: GPLv2+
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Url: http://www.bmsi.com/python/milter.html
# python-2.6.4 gets RuntimeError: not holding the import lock
Requires: %{pythonbase} >= 2.6.5, sendmail-milter >= 8.13
%if 0%{?fedora} >= 23
# Need python2.6 specific pydns, not the version for system python
Recommends: %{pythonbase}-pydns
%endif
# Needed for callbacks, not a core function but highly useful for milters
BuildRequires: ed, %{pythonbase}-devel, sendmail-devel >= 8.13

%description
This is a python extension module to enable python scripts to
attach to sendmail's libmilter functionality.  Additional python
modules provide for navigating and modifying MIME parts, sending
DSNs, and doing CBV.

%package selinux
Summary: SELinux policy module for pymilter
Group: System Environment/Base
Requires: policycoreutils, selinux-policy, %{name}
BuildRequires: policycoreutils, checkpolicy
%if 0%{?epel} >= 6
BuildRequires: policycoreutils-python
%else
BuildRequires: policycoreutils-python-utils
%endif

%description selinux
SELinux policy module for using pymilter with sendmail with selinux enforcing

%prep
%setup -q -n pymilter-%{version}
%patch -p1 -b .py3
cp %{SOURCE1} pymilter.te

%build
env CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build
checkmodule -m -M -o pymilter.mod pymilter.te
semodule_package -o pymilter.pp -m pymilter.mod

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --root=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/run/milter
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/milter
mkdir -p $RPM_BUILD_ROOT%{libdir}

# install selinux modules
mkdir -p %{buildroot}%{_datadir}/selinux/targeted
cp -p pymilter.pp %{buildroot}%{_datadir}/selinux/targeted

%files
%defattr(-,root,root,-)
%doc README ChangeLog NEWS TODO CREDITS sample.py milter-template.py
%{python_sitearch}/*
%{libdir}
%dir %attr(0755,mail,mail) %{_localstatedir}/run/milter
%dir %attr(0755,mail,mail) %{_localstatedir}/log/milter

%files selinux
%doc pymilter.te
%{_datadir}/selinux/targeted/*

%clean
rm -rf $RPM_BUILD_ROOT

%post selinux
/usr/sbin/semodule -s targeted -i %{_datadir}/selinux/targeted/pymilter.pp \
	&>/dev/null || :

%postun selinux
if [ $1 -eq 0 ] ; then
/usr/sbin/semodule -s targeted -r pymilter &> /dev/null || :
fi

%changelog
* Tue Dec 13 2016 Stuart Gathman <stuart@gathman.org> 1.0.2-1
- Fix the last setsymlist misspelling.  Support in test framework and tests.
- Add @symlist decorator.
- Change body callback and a few other APIs to use bytes instead of str.

* Tue Sep 20 2016 Stuart Gathman <stuart@gathman.org> 1.0.1-1
- Support python3

* Sat Mar  1 2014 Stuart Gathman <stuart@gathman.org> 1.0-2
- Remove start.sh to track EPEL repository, suggest daemonize as replacement
- Selinux subpackage should not care about pymilter version

* Wed Jun 26 2013 Stuart Gathman <stuart@gathman.org> 1.0-1
- Allow ACCEPT as untrapped exception policy
- Optional dir for getaddrset and getaddrdict in Milter.config
- Show registered milter name in untrapped exception message.
- Include selinux subpackage
- Provide Milter.greylist export and Milter.greylist import to migrate data

* Sat Mar  9 2013 Stuart Gathman <stuart@bmsi.com> 0.9.8-1
- Add Milter.test module for unit testing milters.
- Fix typo that prevented setsymlist from being active.
- Change untrapped exception message to:
- "pymilter: untrapped exception in milter app"

* Thu Apr 12 2012 Stuart Gathman <stuart@bmsi.com> 0.9.7-1
- Raise RuntimeError when result != CONTINUE for @noreply and @nocallback
- Remove redundant table in miltermodule
- Fix CNAME chain duplicating TXT records in Milter.dns (from pyspf).

* Sat Feb 25 2012 Stuart Gathman <stuart@bmsi.com> 0.9.6-1
- Raise ValueError on unescaped '%' passed to setreply
- Grace time at end of Greylist window

* Fri Aug 19 2011 Stuart Gathman <stuart@bmsi.com> 0.9.5-1
- Print milter.error for invalid callback return type.
  (Since stacktrace is empty, the TypeError exception is confusing.)
- Fix milter-template.py
- Tweak Milter.utils.addr2bin and Milter.dynip to handle IP6

* Tue Mar 02 2010 Stuart Gathman <stuart@bmsi.com> 0.9.4-1
- Handle IP6 in Milter.utils.iniplist()
- python-2.6

* Thu Jul 02 2009 Stuart Gathman <stuart@bmsi.com> 0.9.3-1
- Handle source route in Milter.utils.parse_addr()
- Fix default arg in chgfrom.
- Disable negotiate callback for libmilter < 8.14.3 (1,0,1)

* Tue Jun 02 2009 Stuart Gathman <stuart@bmsi.com> 0.9.2-3
- Change result of @noreply callbacks to NOREPLY when so negotiated.

* Tue Jun 02 2009 Stuart Gathman <stuart@bmsi.com> 0.9.2-2
- Cache callback negotiation

* Thu May 28 2009 Stuart Gathman <stuart@bmsi.com> 0.9.2-1
- Add new callback support: data,negotiate,unknown
- Auto-negotiate protocol steps 

* Thu Feb 05 2009 Stuart Gathman <stuart@bmsi.com> 0.9.1-1
- Fix missing address of optional param to addrcpt

* Wed Jan 07 2009 Stuart Gathman <stuart@bmsi.com> 0.9.0-4
- Stop using INSTALLED_FILES to make Fedora happy
- Remove config flag from start.sh glue
- Own /var/log/milter
- Use _localstatedir

* Wed Jan 07 2009 Stuart Gathman <stuart@bmsi.com> 0.9.0-2
- Changes to meet Fedora standards

* Mon Nov 24 2008 Stuart Gathman <stuart@bmsi.com> 0.9.0-1
- Split pymilter into its own CVS module
- Support chgfrom and addrcpt_par
- Support NS records in Milter.dns

* Mon Aug 25 2008 Stuart Gathman <stuart@bmsi.com> 0.8.10-2
- /var/run/milter directory must be owned by mail

* Mon Aug 25 2008 Stuart Gathman <stuart@bmsi.com> 0.8.10-1
- improved parsing into email and fullname (still 2 self test failures)
- implement no-DSN CBV, reduce full DSNs

* Mon Sep 24 2007 Stuart Gathman <stuart@bmsi.com> 0.8.9-1
- Use ifarch hack to build milter and milter-spf packages as noarch
- Remove spf dependency from dsn.py, add dns.py

* Fri Jan 05 2007 Stuart Gathman <stuart@bmsi.com> 0.8.8-1
- move AddrCache, parse_addr, iniplist to Milter package
- move parse_header to Milter.utils
- fix plock for missing source and can't change owner/group
- split out pymilter and pymilter-spf packages
- move milter apps to /usr/lib/pymilter

* Sat Nov 04 2006 Stuart Gathman <stuart@bmsi.com> 0.8.7-1
- SPF moved to pyspf RPM

* Tue May 23 2006 Stuart Gathman <stuart@bmsi.com> 0.8.6-2
- Support CBV timeout
