%define name milter
%define version 0.8.7
%define release 1
# what version of RH are we building for?
%define redhat7 0

# Options for Redhat version 6.x:
# rpm -ba|--rebuild --define "rh7 1"
%{?rh7:%define redhat7 1}

# some systems dont have initrddir defined
%{?_initrddir:%define _initrddir /etc/rc.d/init.d}

%if %{redhat7} # Redhat 7.x and earlier (multiple ps lines per thread)
%define sysvinit milter.rc7
%else	
%define sysvinit milter.rc
%endif
# RH9, other systems (single ps line per process)
%ifos Linux
%define python python2.4
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
Requires: %{python} >= 2.4, sendmail >= 8.13
%ifos Linux
Requires: chkconfig
%endif
BuildRequires: %{python}-devel >= 2.4, sendmail-devel >= 8.13

%description
This is a python extension module to enable python scripts to
attach to sendmail's libmilter functionality.  Additional python
modules provide for navigating and modifying MIME parts, sending
DSNs, and doing CBV.

%prep
%setup
#patch -p0 -b .bms

%build
%if %{redhat7}
  LDFLAGS="-s"
%else # Redhat builds debug packages after 7.3
  LDFLAGS="-g"
%endif
env CFLAGS="$RPM_OPT_FLAGS" LDFLAGS="$LDFLAGS" %{python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{python} setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
mkdir -p $RPM_BUILD_ROOT/var/log/milter
mkdir -p $RPM_BUILD_ROOT/etc/mail
mkdir $RPM_BUILD_ROOT/var/log/milter/save
cp bms.py *.txt $RPM_BUILD_ROOT/var/log/milter
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
%ifos aix4.1
R=
%else
R='-r'
%endif
cat >$RPM_BUILD_ROOT/etc/cron.daily/milter <<'EOF'
#!/bin/sh

find /var/log/milter/save -mtime +7 | xargs $R rm
# work around memory leak
/etc/init.d/milter condrestart
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
mkdir -p $RPM_BUILD_ROOT/usr/share/sendmail-cf/hack
cp -p rhsbl.m4 $RPM_BUILD_ROOT/usr/share/sendmail-cf/hack

%ifos aix4.1
%post
mkssys -s milter -p /var/log/milter/start.sh -u 25 -S -n 15 -f 9 -G mail || :

%preun
if [ $1 = 0 ]; then
  rmssys -s milter || :
fi
%else
%post
#echo "pythonsock has moved to /var/run/milter, update /etc/mail/sendmail.cf"
/sbin/chkconfig --add milter

%preun
if [ $1 = 0 ]; then
  /sbin/chkconfig --del milter
fi
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc README HOWTO ChangeLog NEWS TODO CREDITS sample.py
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
%config(noreplace) /var/log/milter/strike3.txt
%config(noreplace) /var/log/milter/softfail.txt
%config(noreplace) /var/log/milter/neutral.txt
%config(noreplace) /var/log/milter/quarantine.txt
%config(noreplace) /var/log/milter/permerror.txt
%config(noreplace) /etc/mail/pymilter.cfg
/usr/share/sendmail-cf/hack/rhsbl.m4

%changelog
* Sat Nov 04 2006 Stuart Gathman <stuart@bmsi.com> 0.8.7-1
- More lame bounce heuristics
- SPF moved to pyspf RPM
- wiretap archive option
- Do plain CBV if missing template
* Tue May 23 2006 Stuart Gathman <stuart@bmsi.com> 0.8.6-2
- Support CBV timeout
- Support fail template, headers in templates
- Create GOSSiP record only when connection will procede to DATA.
- More SPF lax heuristics
- Don't require SPF pass for white/black listing mail from trusted relay.
- Support localpart wildcard for white and black lists.
* Thu Feb 23 2006 Stuart Gathman <stuart@bmsi.com> 0.8.6-1
- Delay reject of unsigned RCPT for postmaster and abuse only
- Fix dsn reporting of hard permerror
- Resolve FIXME for wrap_close in miltermodule.c
- Add Message-ID to DSNs
- Use signed Message-ID in delayed reject to blacklist senders
- Auto-train via blacklist and auto-whitelist
- Don't check userlist for signed MFROM
- Accept but skip DSPAM and training for whitelisted senders without SPF PASS
- Report GC stats 
- Support CIDR matching for IP lists
- Support pysrs sign feature
- Support localpart specific SPF policy in access file
* Thu Dec 29 2005 Stuart Gathman <stuart@bmsi.com> 0.8.5-1
- Simple trusted_forwarder implementation.
- Fix access_file neutral policy
- Move Received-SPF header to beginning of headers
- Supply keyword info for all results in Received-SPF header.
- Move guessed SPF result to separate header
- Activate smfi_insheader only when SMFIR_INSHEADER defined
- Handle NULL MX in spf.py
- in-process GOSSiP server support (to be extended later)
- Expire CBV cache and renew auto-whitelist entries
* Fri Oct 21 2005 Stuart Gathman <stuart@bmsi.com> 0.8.4-2
- Don't supply sender when MFROM is subdomain of header from/sender.
- Don't send quarantine DSN for DSNs
- Skip dspam for replies/DSNs to signed MFROM
* Thu Oct 20 2005 Stuart Gathman <stuart@bmsi.com> 0.8.4-1
- Fix SPF policy via sendmail access map (case insensitive keys).
- Auto whitelist senders, train screener on whitelisted messages
- Optional idx parameter to addheader to invoke smfi_insheader
- Activate progress when SMFIR_PROGRESS defined
* Wed Oct 12 2005 Stuart Gathman <stuart@bmsi.com> 0.8.3-1
- Keep screened honeypot mail, but optionally discard honeypot only mail.
- spf_accept_fail option for braindead SPF senders (treats fail like softfail)
- Consider SMTP AUTH connections internal.
- Send DSN for SPF errors corrected by extended processing.
- Send DSN before SCREENED mail is quarantined
- Option to set SPF policy via sendmail access map.
- Option to supply Sender header from MAIL FROM when missing.
- Use logging package to keep log lines atomic.
* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-4
- Limit each CNAME chain independently like PTR and MX
* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-3
- Limit CNAME lookups (regression)
* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-2
- Handle corrupt ZIP attachments
* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-1
- Strict processing limits per SPF RFC
- Fixed several parsing bugs under RFC 
- Support official IANA SPF record (type99)
- Honeypot support (requires pydspam-1.1.9)
- Extended SPF processing results beyond strict RFC limits
- Support original SES for local bounce protection (requires pysrs-0.30.10)
- Callback exception processing option in milter module
* Thu Jun 16 2005 Stuart Gathman <stuart@bmsi.com> 0.8.1-1
- Fix zip in zip loop in mime.py
- Fix HeaderParseError in bms.py header callback
- Check internal_domains for outgoing mail
- Fix inconsistent results from send_dsn
* Mon Jun 06 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-3
- properly log pydspam exceptions
* Sat Jun 04 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-2
- Include default softfail, strike3 templates
* Wed May 25 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-1
- Move Milter module to subpackage.
- DSN support for Three strikes rule and SPF SOFTFAIL
- Move /*mime*/ and dynip to Milter subpackage
- Fix SPF unknown mechanism list not cleared
- Make banned extensions configurable.
- Option to scan zipfiles for bad extensions.
* Tue Feb 08 2005 Stuart Gathman <stuart@bmsi.com> 0.7.3-1.EL3
- Support EL3 and Python2.4 (some scanning/defang support broken)
* Mon Aug 30 2004 Stuart Gathman <stuart@bmsi.com> 0.7.2-1
- Fix various SPF bugs
- Recognize dynamic PTR names, and don't count them as authentication.
- Three strikes and yer out rule.
- Block softfail by default unless valid PTR or HELO
- Return unknown for null mechanism
- Return unknown for invalid ip address in mechanism
- Try best guess on HELO also
- Expand setreply for common errors
- make rhsbl.m4 hack available for sendmail.mc
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
