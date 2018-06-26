Name:           i2pd
Version:        2.19.0
Release:        1%{?dist}
Summary:        I2P router written in C++
Conflicts:      i2pd-git

License:        BSD
URL:            https://github.com/PurpleI2P/i2pd
Source0:        https://github.com/PurpleI2P/i2pd/archive/%{version}/%name-%version.tar.gz

%if 0%{?rhel}  == 7
BuildRequires:  cmake3
%else
BuildRequires:  cmake
%endif

BuildRequires:  chrpath
BuildRequires:  gcc-c++
BuildRequires:  zlib-devel
BuildRequires:  boost-devel
BuildRequires:  openssl-devel
BuildRequires:  miniupnpc-devel
BuildRequires:  systemd-units

Requires:	systemd
Requires(pre):  %{_sbindir}/useradd %{_sbindir}/groupadd

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
    -DBUILD_SHARED_LIBS:BOOL=OFF
%endif

make %{?_smp_mflags}


%install
cd build
chrpath -d i2pd
install -D -m 755 i2pd %{buildroot}%{_sbindir}/i2pd
install -D -m 755 %{_builddir}/%{name}-%{version}/contrib/i2pd.conf %{buildroot}%{_sysconfdir}/i2pd/i2pd.conf
install -D -m 755 %{_builddir}/%{name}-%{version}/contrib/tunnels.conf %{buildroot}%{_sysconfdir}/i2pd/tunnels.conf
install -d -m 755 %{buildroot}%{_datadir}/i2pd
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/certificates/ %{buildroot}%{_datadir}/i2pd/certificates
install -D -m 644 %{_builddir}/%{name}-%{version}/contrib/rpm/i2pd.service %{buildroot}%{_unitdir}/i2pd.service
install -d -m 700 %{buildroot}%{_sharedstatedir}/i2pd
install -d -m 700 %{buildroot}%{_localstatedir}/log/i2pd
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
%doc LICENSE README.md
%{_sbindir}/i2pd
%{_datadir}/i2pd/certificates
%config(noreplace) %{_sysconfdir}/i2pd/*
/%{_unitdir}/i2pd.service
%dir %attr(0700,i2pd,i2pd) %{_localstatedir}/log/i2pd
%dir %attr(0700,i2pd,i2pd) %{_sharedstatedir}/i2pd
%{_sharedstatedir}/i2pd/certificates


%changelog
* Tue Jun 26 2018 orignal <i2porignal@yandex.ru> - 2.19.0
- update to 2.19.0

* Mon Feb 05 2018 r4sas <r4sas@i2pmail.org> - 2.18.0-2
- Fixed blocking system shutdown for 10 minutes (#1089)

* Thu Feb 01 2018 r4sas <r4sas@i2pmail.org> - 2.18.0-1
- Added to conflicts i2pd-git package
- Fixed release versioning
- Fixed paths with double slashes

* Tue Jan 30 2018 orignal <i2porignal@yandex.ru> - 2.18.0
- update to 2.18.0

* Sat Jan 27 2018 l-n-s <supervillain@riseup.net> - 2.17.0-1
- Added certificates and default configuration files
- Merge i2pd with i2pd-systemd package
- Fixed package changelogs to comply with guidelines

* Mon Dec 04 2017 orignal <i2porignal@yandex.ru> - 2.17.0
- update to 2.17.0

* Mon Nov 13 2017 orignal <i2porignal@yandex.ru> - 2.16.0
- update to 2.16.0

* Thu Aug 17 2017 orignal <i2porignal@yandex.ru> - 2.15.0
- update to 2.15.0

* Thu Jun 01 2017 orignal <i2porignal@yandex.ru> - 2.14.0
- update to 2.14.0

* Thu Apr 06 2017 orignal <i2porignal@yandex.ru> - 2.13.0
- update to 2.13.0

* Tue Feb 14 2017 orignal <i2porignal@yandex.ru> - 2.12.0
- update to 2.12.0

* Mon Dec 19 2016 orignal <i2porignal@yandex.ru> - 2.11.0
- update to 2.11.0

* Thu Oct 20 2016 Anatolii Vorona <vorona.tolik@gmail.com> - 2.10.0-3
- add support C7
- move rpm-related files to contrib folder

* Sun Oct 16 2016 Oleg Girko <ol@infoserver.lv> - 2.10.0-1
- update to 2.10.0

* Sun Aug 14 2016 Oleg Girko <ol@infoserver.lv> - 2.9.0-1
- update to 2.9.0

* Sun Aug 07 2016 Oleg Girko <ol@infoserver.lv> - 2.8.0-2
- rename daemon subpackage to systemd

* Sat Aug 06 2016 Oleg Girko <ol@infoserver.lv> - 2.8.0-1
- update to 2.8.0
- remove wrong rpath from i2pd binary
- add daemon subpackage with systemd unit file

* Sat May 21 2016 Oleg Girko <ol@infoserver.lv> - 2.7.0-1
- update to 2.7.0

* Tue Apr 05 2016 Oleg Girko <ol@infoserver.lv> - 2.6.0-1
- update to 2.6.0

* Tue Jan 26 2016 Yaroslav Sidlovsky <zawertun@gmail.com> - 2.3.0-1
- initial package for version 2.3.0
