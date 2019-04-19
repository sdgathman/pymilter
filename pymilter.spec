# we don't want to provide private python extension libs
%global sum Python interface to sendmail milter API
%global __provides_exclude_from ^(%{python2_sitearch})/.*\\.so$
%if 0%{?epel} == 7
%global python3 python36
%else
%global python3 python3
%endif

Summary: %{sum}
Name: python-pymilter
Version: 1.0.4
Release: 1%{?dist}
Url: http://bmsi.com/pymilter
Source: https://github.com/sdgathman/pymilter/archive/pymilter-%{version}.tar.gz
#Source1: tmpfiles-python-pymilter.conf
# remove unit tests that require network for check
Patch: pymilter-check.patch
License: GPLv2+
Group: Development/Libraries
BuildRequires: python2-devel, %{python3}-devel, sendmail-devel >= 8.13
# python-2.6.4 gets RuntimeError: not holding the import lock
# Need python2.6 specific pydns, not the version for system python
BuildRequires:  gcc

%global _description\
This is a python extension module to enable python scripts to\
attach to sendmail's libmilter functionality.  Additional python\
modules provide for navigating and modifying MIME parts, sending\
DSNs, and doing CBV.

%description %_description

%package -n python2-pymilter
Summary: %{sum}
%if 0%{?epel} >= 6
Requires: python-pydns
%else
Requires: python2-pydns
%endif
Requires: %{name}-common = %{version}-%{release}
%{?python_provide:%python_provide python2-pymilter}

%description -n python2-pymilter %_description

%package -n %{python3}-pymilter
Summary: %{sum}
%if 0%{?fedora} >= 26
Requires: %{python3}-py3dns
%endif
Requires: %{name}-common = %{version}-%{release}
%{?python_provide:%python_provide %{python3}-pymilter}

%description -n %{python3}-pymilter %_description

%package common
Summary: Common files and directories for python milters
BuildArch: noarch

%description common
Common files and directories used for python milters

%package selinux
Summary: SELinux policy module for pymilter
Group: System Environment/Base
Requires: policycoreutils, selinux-policy-targeted
Requires: %{name} = %{version}-%{release}
BuildArch: noarch
BuildRequires: policycoreutils, checkpolicy, selinux-policy-devel
%if 0%{?epel} >= 6
BuildRequires: policycoreutils-python
%else
BuildRequires: policycoreutils-python-utils
%endif

%description selinux
Give sendmail_t additional access to stream sockets used to communicate
with milters.

%prep
%setup -q -n pymilter-pymilter-%{version}
#patch -p1 -b .check

%build
%py2_build
%py3_build
checkmodule -m -M -o pymilter.mod pymilter.te
semodule_package -o pymilter.pp -m pymilter.mod

%install
%py2_install 
%py3_install 

mkdir -p %{buildroot}/run/milter
mkdir -p %{buildroot}%{_localstatedir}/log/milter
mkdir -p %{buildroot}%{_libexecdir}/milter
#mkdir -p %{buildroot}%{_prefix}/lib/tmpfiles.d
#install -m 0644 %{SOURCE1} %{buildroot}%{_prefix}/lib/tmpfiles.d/%{name}.conf

# install selinux modules
mkdir -p %{buildroot}%{_datadir}/selinux/targeted
cp -p pymilter.pp %{buildroot}%{_datadir}/selinux/targeted

%check
py2path=$(ls -d build/lib.linux-*-2.*)
py3path=$(ls -d build/lib.linux-*-3.*)
PYTHONPATH=${py2path}:. python2 test.py &&
PYTHONPATH=${py3path}:. python3 test.py

%files -n python2-pymilter
%license COPYING
%doc README ChangeLog NEWS TODO CREDITS sample.py milter-template.py
%{python2_sitearch}/*

%files -n %{python3}-pymilter
%license COPYING
%doc README ChangeLog NEWS TODO CREDITS sample.py milter-template.py
%{python3_sitearch}/*

%files common
%dir %{_libexecdir}/milter
%{_prefix}/lib/tmpfiles.d/%{name}.conf
%dir %attr(0755,mail,mail) %{_localstatedir}/log/milter
%dir %attr(0755,mail,mail) /run/milter

%files selinux
%doc pymilter.te
%{_datadir}/selinux/targeted/*

%post selinux
%{_sbindir}/semodule -s targeted -i %{_datadir}/selinux/targeted/pymilter.pp \
        &>/dev/null || :

%postun selinux
if [ $1 -eq 0 ] ; then
%{_sbindir}/semodule -s targeted -r pymilter &> /dev/null || :
fi

%changelog
* Wed Apr 17 2019 Stuart Gathman <stuart@gathman.org> - 1.0.4-1
- New upstream release: cleanup unused files, additional platform support
- Minor doc updates

* Sun Dec 23 2018 Stuart Gathman <stuart@gathman.org> - 1.0.3-1
- New upstream release
- patch step for python3 no longer required in build

* Sat Aug  4 2018 Stuart Gathman <stuart@gathman.org> - 1.0.2-4
- Add unit tests to %%check

* Sat Aug  4 2018 Stuart Gathman <stuart@gathman.org> - 1.0.2-3
- use libexec instead of libdir

* Sat Aug  4 2018 Stuart Gathman <stuart@gathman.org> - 1.0.2-2
- add python34 subpackage on el7

* Sat Aug  4 2018 Stuart Gathman <stuart@gathman.org> - 1.0.2-1
- build for both python2 and python3
- add selinux policy allowing sendmail_t access to milters

* Tue Jul 17 2018 Miro Hrončok <mhroncok@redhat.com> - 1.0-13
- Update Python macros to new packaging standards
  (See https://fedoraproject.org/wiki/Changes/Move_usr_bin_python_into_separate_package)

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Fri Feb 09 2018 Iryna Shcherbina <ishcherb@redhat.com> - 1.0-11
- Update Python 2 dependency declarations to new packaging standards
  (See https://fedoraproject.org/wiki/FinalizingFedoraSwitchtoPython3)

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Fri Feb 09 2018 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 1.0-9
- Escape macros in %%changelog

* Sat Aug 19 2017 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl> - 1.0-8
- Python 2 binary package renamed to python2-pymilter
  See https://fedoraproject.org/wiki/FinalizingFedoraSwitchtoPython3

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild
>>>>>>> 021796e51e5919812f1c300d1830ef9ed378db2d

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Jul 19 2016 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.0-4
- https://fedoraproject.org/wiki/Changes/Automatic_Provides_for_Python_RPM_Packages

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Thu Jun 18 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Sat Sep 27 2014 Paul Wouters <pwouters@redhat.com> - 1.0-1
- Updated to 1.0
- Use tmpfiles and /run

* Sun Aug 17 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.8-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.8-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Jan 10 2014 Paul Wouters <pwouters@redhat.com> - 0.9.8-4
- Add COPYING
- Fix buildroot macros and dist macro

* Fri Jan 10 2014 Paul Wouters <pwouters@redhat.com> - 0.9.8-3
- rebuilt with proper file permission

* Tue Jan 07 2014 Paul Wouters <pwouters@redhat.com> - 0.9.8-2
- Fixup for fedora release

* Sat Mar  9 2013 Stuart Gathman <stuart@bmsi.com> 0.9.8-1
- Add Milter.test module for unit testing milters.
- Fix typo that prevented setsymlist from being active.
- Change untrapped exception message to:
- "pymilter: untrapped exception in milter app"

* Sat Feb 25 2012 Stuart Gathman <stuart@bmsi.com> 0.9.7-1
- Raise RuntimeError when result != CONTINUE for @noreply and @nocallback
- Remove redundant table in miltermodule
- Fix CNAME chain duplicating TXT records in Milter.dns (from pyspf).

* Sat Feb 25 2012 Stuart Gathman <stuart@bmsi.com> 0.9.6-1
- Raise ValueError on unescaped '%%' passed to setreply
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
