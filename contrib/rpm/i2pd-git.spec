%define git_hash %(git rev-parse HEAD | cut -c -7)

Name:          i2pd-git
Version:       2.39.0
Release:       git%{git_hash}%{?dist}
Summary:       I2P router written in C++
Conflicts:     i2pd

License:       BSD
URL:           https://github.com/PurpleI2P/i2pd
Source0:       https://github.com/PurpleI2P/i2pd/archive/openssl/i2pd-openssl.tar.gz

%if 0%{?rhel} == 7
BuildRequires: cmake3
%else
BuildRequires: cmake
%endif

BuildRequires: chrpath
BuildRequires: gcc-c++
BuildRequires: zlib-devel
BuildRequires: boost-devel
BuildRequires: openssl-devel
BuildRequires: miniupnpc-devel
BuildRequires: systemd-units

Requires:      logrotate
Requires:      systemd
Requires(pre): %{_sbindir}/useradd %{_sbindir}/groupadd

%description
C++ implementation of I2P.

%prep
%setup -q


%build
cd build
%if 0%{?rhel} == 7
%cmake3 \
    -DWITH_LIBRARY=OFF \
    -DWITH_UPNP=ON \
    -DWITH_HARDENING=ON \
    -DBUILD_SHARED_LIBS:BOOL=OFF
%else
%cmake \
    -DWITH_LIBRARY=OFF \
    -DWITH_UPNP=ON \
    -DWITH_HARDENING=ON \
%if 0%{?fedora} > 29
    -DBUILD_SHARED_LIBS:BOOL=OFF \
    .
%else
    -DBUILD_SHARED_LIBS:BOOL=OFF
%endif
%endif


%if 0%{?fedora} >= 35
pushd redhat-linux-build
%else
%if 0%{?fedora} >= 33
pushd %{_target_platform}
%endif
%endif

%if 0%{?mageia} > 7
pushd build
%endif

make %{?_smp_mflags}

%if 0%{?fedora} >= 33
popd
%endif

%if 0%{?mageia} > 7
popd
%endif

%install
pushd build

%if 0%{?fedora} >= 35
pushd redhat-linux-build
%else
%if 0%{?fedora} >= 33
pushd %{_target_platform}
%endif
%endif

%if 0%{?mageia}
pushd build
%endif

chrpath -d i2pd
%{__install} -D -m 755 i2pd %{buildroot}%{_sbindir}/i2pd
%{__install} -d -m 755 %{buildroot}%{_datadir}/i2pd
%{__install} -d -m 700 %{buildroot}%{_sharedstatedir}/i2pd
%{__install} -d -m 700 %{buildroot}%{_localstatedir}/log/i2pd
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/i2pd.conf %{buildroot}%{_sysconfdir}/i2pd/i2pd.conf
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/subscriptions.txt %{buildroot}%{_sysconfdir}/i2pd/subscriptions.txt
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/tunnels.conf %{buildroot}%{_sysconfdir}/i2pd/tunnels.conf
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/i2pd.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/i2pd
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/i2pd.service %{buildroot}%{_unitdir}/i2pd.service
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/debian/i2pd.1 %{buildroot}%{_mandir}/man1/i2pd.1
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/certificates/ %{buildroot}%{_datadir}/i2pd/certificates
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/tunnels.d/ %{buildroot}%{_sysconfdir}/i2pd/tunnels.conf.d
ln -s %{_datadir}/%{name}/certificates %{buildroot}%{_sharedstatedir}/i2pd/certificates


%pre
getent group i2pd >/dev/null || %{_sbindir}/groupadd -r i2pd
getent passwd i2pd >/dev/null || \
  %{_sbindir}/useradd -r -g i2pd -s %{_sbindir}/nologin \
                      -d %{_sharedstatedir}/i2pd -c 'I2P Service' i2pd


%post
%systemd_post i2pd.service


%preun
%systemd_preun i2pd.service


%postun
%systemd_postun_with_restart i2pd.service


%files
%doc LICENSE README.md contrib/i2pd.conf contrib/subscriptions.txt contrib/tunnels.conf contrib/tunnels.d
%{_sbindir}/i2pd
%config(noreplace) %{_sysconfdir}/i2pd/*.conf
%config(noreplace) %{_sysconfdir}/i2pd/tunnels.conf.d/*.conf
%config %{_sysconfdir}/i2pd/subscriptions.txt
%doc %{_sysconfdir}/i2pd/tunnels.conf.d/README
%{_sysconfdir}/logrotate.d/i2pd
%{_unitdir}/i2pd.service
%{_mandir}/man1/i2pd.1*
%dir %attr(0700,i2pd,i2pd) %{_sharedstatedir}/i2pd
%dir %attr(0700,i2pd,i2pd) %{_localstatedir}/log/i2pd
%{_datadir}/i2pd/certificates
%{_sharedstatedir}/i2pd/certificates


%changelog
* Mon Aug 24 2021 r4sas <r4sas@i2pmail.org> - 2.39.0-2
- changed if statements to cover fedora 35

* Mon Aug 23 2021 orignal <i2porignal@yandex.ru> - 2.39.0
- update to 2.39.0
- fixed build on fedora 36

* Mon May 17 2021 orignal <i2porignal@yandex.ru> - 2.38.0
- update to 2.38.0

* Mon Mar 15 2021 orignal <i2porignal@yandex.ru> - 2.37.0
- update to 2.37.0

* Mon Feb 15 2021 orignal <i2porignal@yandex.ru> - 2.36.0
- update to 2.36.0

* Mon Nov 30 2020 orignal <i2porignal@yandex.ru> - 2.35.0
- update to 2.35.0

* Tue Oct 27 2020 orignal <i2porignal@yandex.ru> - 2.34.0
- update to 2.34.0

* Mon Aug 24 2020 orignal <i2porignal@yandex.ru> - 2.33.0
- update to 2.33.0

* Tue Jun 02 2020 r4sas <r4sas@i2pmail.org> - 2.32.1
- update to 2.32.1

* Mon May 25 2020 r4sas <r4sas@i2pmail.org> - 2.32.0
- update to 2.32.0
- updated systemd service file (#1394)

* Thu May 7 2020 Anatolii Vorona <vorona.tolik@gmail.com> - 2.31.0-3
- added RPM logrotate config

* Fri Apr 10 2020 orignal <i2porignal@yandex.ru> - 2.31.0
- update to 2.31.0

* Tue Feb 25 2020 orignal <i2porignal@yandex.ru> - 2.30.0
- update to 2.30.0

* Mon Oct 21 2019 orignal <i2porignal@yandex.ru> - 2.29.0
- update to 2.29.0

* Tue Aug 27 2019 orignal <i2porignal@yandex.ru> - 2.28.0
- update to 2.28.0

* Wed Jul 3 2019 orignal <i2porignal@yandex.ru> - 2.27.0
- update to 2.27.0

* Fri Jun 7 2019 orignal <i2porignal@yandex.ru> - 2.26.0
- update to 2.26.0

* Thu May 9 2019 orignal <i2porignal@yandex.ru> - 2.25.0
- update to 2.25.0

* Thu Mar 21 2019 orignal <i2porignal@yandex.ru> - 2.24.0
- update to 2.24.0

* Mon Jan 21 2019 orignal <i2porignal@yandex.ru> - 2.23.0
- update to 2.23.0

* Fri Nov 09 2018 r4sas <r4sas@i2pmail.org> - 2.22.0
- add support of tunnelsdir option

* Thu Feb 01 2018 r4sas <r4sas@i2pmail.org> - 2.18.0
- Initial i2pd-git based on i2pd 2.18.0-1 spec
