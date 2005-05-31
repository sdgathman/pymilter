%define name milter
%define version 0.7.1
%define release 1
# Redhat 7.x and earlier (multiple ps lines per thread)
%define sysvinit milter.rc7
# RH9, other systems (single ps line per process)
#define sysvinit milter.rc
%ifos Linux
%define python python2.3
%else
%define python python
%endif

Summary: Python interface to sendmail milter API
Name: %{name}
Version: %{version}
Release: %{release}
Source: %{name}-%{version}.tar.gz
#Patch: %{name}-%{version}.patch
Copyright: GPL
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
Prefix: %{_prefix}
Vendor: Stuart D. Gathman <stuart@bmsi.com>
Packager: Stuart D. Gathman <stuart@bmsi.com>
Url: http://www.bmsi.com/python/milter.html
Requires: %{python} >= 2.2.2, sendmail >= 8.12.10
BuildRequires: %{python}-devel >= 2.2.2, sendmail-devel >= 8.12.10

%description
This is a python extension module to enable python scripts to
attach to sendmail's libmilter functionality.  Additional python
modules provide for navigating and modifying MIME parts.

%prep
%setup
#%patch -p1

%build
env CFLAGS="$RPM_OPT_FLAGS" %{python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
mkdir -p $RPM_BUILD_ROOT/var/log/milter
mkdir -p $RPM_BUILD_ROOT/etc/mail
mkdir $RPM_BUILD_ROOT/var/log/milter/save
cp bms.py $RPM_BUILD_ROOT/var/log/milter
cp milter.cfg $RPM_BUILD_ROOT/etc/mail/pymilter.cfg

# logfile rotation
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
cat >$RPM_BUILD_ROOT/etc/logrotate.d/milter <<'EOF'
/var/log/milter/milter.log {
  copytruncate
  compress
}
EOF

# purge saved defanged message copies
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily
cat >$RPM_BUILD_ROOT/etc/cron.daily/milter <<'EOF'
#!/bin/sh

find /var/log/milter/save -mtime +7 | xargs -r rm
EOF
chmod a+x $RPM_BUILD_ROOT/etc/cron.daily/milter

%ifos aix4.1
cat >$RPM_BUILD_ROOT/var/log/milter/start.sh <<'EOF'
#!/bin/sh
cd /var/log/milter
# uncomment to enable sgmlop if installed
#export PYTHONPATH=/usr/local/lib/python2.1/site-packages
exec /usr/local/bin/python bms.py >>milter.log 2>&1
EOF
%else
cat >$RPM_BUILD_ROOT/var/log/milter/start.sh <<'EOF'
#!/bin/sh
cd /var/log/milter
exec >>milter.log 2>&1
%{python} bms.py &
echo $! >/var/run/milter/milter.pid
EOF
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
cp %{sysvinit} $RPM_BUILD_ROOT/etc/rc.d/init.d/milter
ed $RPM_BUILD_ROOT/etc/rc.d/init.d/milter <<'EOF'
/^python=/
c
python="%{python}"
.
w
q
EOF
%endif
chmod a+x $RPM_BUILD_ROOT/var/log/milter/start.sh

mkdir -p $RPM_BUILD_ROOT/var/run/milter

%ifos aix4.1
%post
mkssys -s milter -p /var/log/milter/start.sh -u 25 -S -n 15 -f 9 -G mail || :

%preun
if [ $1 = 0 ]; then
  rmssys -s milter || :
fi
%else
%post
echo "pythonsock has moved to /var/run/milter, update /etc/mail/sendmail.cf"
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc README NEWS TODO CREDITS sample.py
/etc/logrotate.d/milter
/etc/cron.daily/milter
%ifos aix4.1
%defattr(-,smmsp,mail)
%else
/etc/rc.d/init.d/milter
%defattr(-,mail,mail)
%endif
%dir /var/log/milter
%dir /var/run/milter
%dir /var/log/milter/save
%config /var/log/milter/start.sh
%config /var/log/milter/bms.py
%config(noreplace) /etc/mail/pymilter.cfg

%changelog
* Sun Aug 22 2004 Stuart Gathman <stuart@bmsi.com> 0.7.1-1
- Handle modifying mislabeled multipart messages without an exception
- Support setbacklog, setmlreply
- allow multi-recipient CBV
- return TEMPFAIL for SPF softfail
* Fri Jul 23 2004 Stuart Gathman <stuart@bmsi.com> 0.7.0-1
- SPF check hello name
- Move pythonsock to /var/run/milter
- Move milter.cfg to /etc/mail/pymilter.cfg
- Check M$ style XML CID records by converting to SPF
- Recognize, but never match ip6 until we properly support it.
- Option to reject when no PTR and no SPF
* Fri Apr 09 2004 Stuart Gathman <stuart@bmsi.com> 0.6.9-1
- Validate spf.py against test suite, and add Received-SPF support to spf.py
- Support best_guess for SPF
- Reject numeric hello names
- Preserve case of local part in sender
- Make libmilter timeout a config option
- Fix setup.py to work with python < 2.2.3
* Tue Apr 06 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-3
- Reject invalid SRS immediately for benefit of callback verifiers
- Fix include bug in spf.py
* Tue Apr 06 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-2
- Bug in check_header
* Mon Apr 05 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-1
- Don't report spoofed unless rcpt looks like SRS
- Check for bounce with multiple rcpts
- Make dspam see Received-SPF headers
- Make sysv init work with RH9
* Thu Mar 25 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-3
- Forgot to make spf_reject_neutral global in bms.py
* Wed Mar 24 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-2
- Defang message/rfc822 content_type with boundary 
- Support SPF delegation
- Reject neutral SPF result for selected domains
* Tue Mar 23 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-1
- SRS forgery check.  Detect thread resource starvation.
- Properly remove local socket with explicit type.
- Decode obfuscated subject headers.
* Wed Mar 11 2004 Stuart Gathman <stuart@bmsi.com> 0.6.6-2
- init script bug with python2.3
* Wed Mar 10 2004 Stuart Gathman <stuart@bmsi.com> 0.6.6-1
- SPF checking, hello blacklist
* Mon Mar 08 2004 Stuart Gathman <stuart@bmsi.com> 0.6.5-2
- memory leak in envfrom and envrcpt
* Mon Mar 01 2004 Stuart Gathman <stuart@bmsi.com> 0.6.5-1
- progress notification
- memory leak in connect
- trusted relay
* Thu Feb 19 2004 Stuart Gathman <stuart@bmsi.com> 0.6.4-2
- smart alias wildcard patch, compile for sendmail-8.12
* Thu Dec 04 2003 Stuart Gathman <stuart@bmsi.com> 0.6.4-1
- many fixes for dspam support
* Wed Oct 22 2003 Stuart Gathman <stuart@bmsi.com> 0.6.3
- dspam SCREEN feature
- streamline dspam false positive handling
* Mon Sep 01 2003 Stuart Gathman <stuart@bmsi.com> 0.6.1
- Full dspam support added
* Mon Aug 26 2003 Stuart Gathman <stuart@bmsi.com>
- Use New email module
* Fri Jun 27 2003 Stuart Gathman <stuart@bmsi.com>
- Add dspam module
