%define __python python2.4
%define version 0.9.0
%define release 1.el4
%define libdir %{_libdir}/pymilter
%define name pymilter
%define redhat7 0

Summary: Python interface to sendmail milter API
Name: %{name}
Version: %{version}
Release: %{release}
Source: %{name}-%{version}.tar.gz
#Patch: %{name}-%{version}.patch
License: GPLv2+
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
Vendor: Stuart D. Gathman <stuart@bmsi.com>
Url: http://www.bmsi.com/python/milter.html
Requires: %{__python} >= 2.4, sendmail >= 8.13
BuildRequires: %{__python}-devel >= 2.4, sendmail-devel >= 8.13

%description
This is a python extension module to enable python scripts to
attach to sendmail's libmilter functionality.  Additional python
modules provide for navigating and modifying MIME parts, sending
DSNs, and doing CBV.

%prep
%setup -q
#patch -p0 -b .bms

%build
%if %{redhat7} 
  LDFLAGS="-s"
%else # Redhat builds debug packages after 7.3
  LDFLAGS="-g"
%endif
env CFLAGS="$RPM_OPT_FLAGS" LDFLAGS="$LDFLAGS" %{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
mkdir -p $RPM_BUILD_ROOT/var/run/milter
mkdir -p $RPM_BUILD_ROOT%{libdir}
%ifos aix4.1
cat >$RPM_BUILD_ROOT%{libdir}/start.sh <<'EOF'
#!/bin/sh
cd /var/log/milter
exec /usr/local/bin/python bms.py >>milter.log 2>&1
EOF
%else # not aix4.1
cp start.sh $RPM_BUILD_ROOT%{libdir}
ed $RPM_BUILD_ROOT%{libdir}/start.sh <<'EOF'
/^python=/
c
python="%{__python}"
.
w
q
EOF
%endif
chmod a+x $RPM_BUILD_ROOT%{libdir}/start.sh
%if !%{redhat7}
#grep '.pyc$' INSTALLED_FILES | sed -e 's/c$/o/' >>INSTALLED_FILES
%endif

# start.sh is used by spfmilter and milter, and could be used by
# other milters running on redhat
%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc README ChangeLog NEWS TODO CREDITS sample.py milter-template.py
%config %{libdir}/start.sh
%dir %attr(0755,mail,mail) /var/run/milter

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
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
