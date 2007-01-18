Summary: NSD is a complete implementation of an authoritative DNS name server
Name: nsd
Version: 3.0.4
Release: 1%{?dist}
License: BSD-like
Url: http://www.nlnetlabs.nl/nsd/
Source: http://www.nlnetlabs.nl/downloads/nsd/%{name}-%{version}.tar.gz
Source1: nsd.init
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: flex, openssl-devel

%description
NSD is a complete implementation of an authoritative DNS name server.
It can function as a primary or secondary DNS server, with DNSSEC support.
For further information about what NSD is and what NSD is not please
consult the REQUIREMENTS document which is a part of this distribution.

%prep
%setup -q 

%configure --enable-bind8-stats --enable-checking \
           --with-pidfile=%{_localstatedir}/run/%{name}/%{name}.pid \
           --with-difffile=%{_localstatedir}/cache/%{name}/ixfr.db \
           --with-xfrdfile=%{_localstatedir}/cache/%{name}/xfrd.state \
           --with-ssl --with-user=nsd

%build
%{__make} %{?_smp_mflags}

%install
rm -rf %{buildroot}
%{__make} DESTDIR=%{buildroot} install
install -d 0755 %{buildroot}%{_initrddir}
install -m 0755 %{SOURCE1} %{buildroot}/%{_initrddir}/nsd
install -d 0700 %{buildroot}%{_localstatedir}/run/%{name}
install -d 0700 %{buildroot}%{_localstatedir}/cache/%{name}

# change .sample to normal config file
mv %{buildroot}%{_sysconfdir}/nsd/nsd.conf.sample \
   %{buildroot}%{_sysconfdir}/nsd/nsd.conf

%clean
rm -rf ${RPM_BUILD_ROOT}

%files 
%defattr(-,root,root,-)
%doc doc/README doc/LICENSE doc/differences.pdf doc/TODO doc/RELNOTES doc/REQUIREMENTS
%doc doc/NSD-FOR-BIND-USERS doc/NSD-DATABASE doc/NSD-DIFFFILE doc/README.icc
%doc doc/CREDITS
%dir %{_sysconfdir}/nsd/
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/nsd/nsd.conf
%attr(0755,root,root) %{_initrddir}/%{name}
%attr(0755,%{name},%{name}) %{_sysconfdir}/nsd
%attr(0700,%{name},%{name}) %dir %{_localstatedir}/run/%{name}
%attr(0700,%{name},%{name}) %dir %{_localstatedir}/cache/%{name}
%{_sbindir}/*
%{_mandir}/*/*

%pre
if getent passwd nsd >/dev/null 2>&1 ; then : ; else /usr/sbin/useradd -d /etc/nsd -r -s /sbin/nologin nsd >/dev/null 2>&1 || exit 1 ; fi
if [ $1 = 2 -a -f /%{_localstatedir}/run/%{name}/%{name}.pid ]; then
	/sbin/service %{name} stop
fi
# "Everyone is doing it, so why can't we?" 
exit 0

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 -eq 0 ]; then
        /sbin/service %{name} stop
        /sbin/chkconfig --del %{name} 
fi

%postun
if [ "$1" -ge "1" ]; then
  /sbin/service %{name} condrestart
fi

%changelog
* Mon Dec 11 2006 Wouter Wijngaards <wouter@nlnetlabs.nl> - 3.0.4-1
- Updated file permissions to make /etc/nsd owned by nsd user.

* Mon Aug 21 2006 Wouter Wijngaards <wouter@nlnetlabs.nl> - 3.0.0-1
- Proposal for 3.0.0 spec file

* Mon Jun 26 2006 Paul Wouters <paul@xelerance.com> - 2.3.5-2
- Bump version for FC-x upgrade path

* Mon Jun 26 2006 Paul Wouters <paul@xelerance.com> - 2.3.5-1
- Upgraded to nsd-2.3.5

* Sun May  7 2006 Paul Wouters <paul@xelerance.com> - 2.3.4-4
- Upgraded to nsd-2.3.4. 
- Removed manual install targets because DESTDIR is now supported
- Re-enabled --checking, checking patch no longer needed and removed.
- Work around in nsd.init for nsd failing to start when there is no ipv6
- Various release bumps due to 'make tag' failures :(

* Thu Dec 15 2005 Paul Wouters <paul@xelerance.com> - 2.3.3-7
- chkconfig and attribute  changes as proposed by Dmitry Butskoy

* Thu Dec 15 2005 Paul Wouters <paul@xelerance.com> - 2.3.3-6
- Moved pid file to /var/run/nsd/nsd.pid.
- Use %{_localstatedir} instead of "/var"

* Tue Dec 13 2005 Paul Wouters <paul@xelerance.com> - 2.3.3-5
- Added BuildRequires for openssl-devel, removed Requires for openssl.

* Mon Dec 12 2005 Paul Wouters <paul@xelerance.com> - 2.3.3-4
- upgraded to nsd-2.3.3

* Wed Dec  7 2005 Tom "spot" Callaway <tcallawa@redhat.com> - 2.3.2-2
- minor cleanups

* Mon Dec  5 2005 Paul Wouters <paul@xelerance.com> - 2.3.2-1
- Upgraded to 2.3.2. Changed post scripts to comply to Fedora
  Extras policies (eg do not start daemon on fresh install)

* Tue Oct  4 2005 Paul Wouters <paul@xelerance.com> - 2.3.1-1
- Initial version
