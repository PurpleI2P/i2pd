Name:           dotnet
Version:        2.25.0
Release:        1%{?dist}
Summary:        DOTNET router written in C++
Conflicts:      dotnet-git

License:        BSD
URL:            https://github.com/PurpleI2P/dotnet
Source0:        https://github.com/PurpleI2P/dotnet/archive/%{version}/%name-%version.tar.gz

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
C++ implementation of DOTNET.

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

make %{?_smp_mflags}


%install
cd build
%if 0%{?mageia}
cd build
%endif
chrpath -d dotnet
install -D -m 755 dotnet %{buildroot}%{_sbindir}/dotnet
install -D -m 755 %{_builddir}/%{name}-%{version}/contrib/dotnet.conf %{buildroot}%{_sysconfdir}/dotnet/dotnet.conf
install -D -m 755 %{_builddir}/%{name}-%{version}/contrib/tunnels.conf %{buildroot}%{_sysconfdir}/dotnet/tunnels.conf
install -d -m 755 %{buildroot}%{_datadir}/dotnet
install -d -m 755 %{buildroot}%{_datadir}/dotnet/tunnels.conf.d
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/certificates/ %{buildroot}%{_datadir}/dotnet/certificates
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/tunnels.d/ %{buildroot}%{_sysconfdir}/dotnet/tunnels.conf.d
install -D -m 644 %{_builddir}/%{name}-%{version}/contrib/rpm/dotnet.service %{buildroot}%{_unitdir}/dotnet.service
install -d -m 700 %{buildroot}%{_sharedstatedir}/dotnet
install -d -m 700 %{buildroot}%{_localstatedir}/log/dotnet
ln -s %{_datadir}/%{name}/certificates %{buildroot}%{_sharedstatedir}/dotnet/certificates
ln -s %{_datadir}/dotnet/tunnels.conf.d %{buildroot}%{_sysconfdir}/dotnet/tunnels.conf.d


%pre
getent group dotnet >/dev/null || %{_sbindir}/groupadd -r dotnet
getent passwd dotnet >/dev/null || \
  %{_sbindir}/useradd -r -g dotnet -s %{_sbindir}/nologin \
                      -d %{_sharedstatedir}/dotnet -c 'DOTNET Service' dotnet


%post
%systemd_post dotnet.service


%preun
%systemd_preun dotnet.service


%postun
%systemd_postun_with_restart dotnet.service


%files
%doc LICENSE README.md
%{_sbindir}/dotnet
%{_datadir}/dotnet/certificates
%config(noreplace) %{_sysconfdir}/dotnet/*
%config(noreplace) %{_sysconfdir}/dotnet/tunnels.conf.d/*
/%{_unitdir}/dotnet.service
%dir %attr(0700,dotnet,dotnet) %{_localstatedir}/log/dotnet
%dir %attr(0700,dotnet,dotnet) %{_sharedstatedir}/dotnet
%{_sharedstatedir}/dotnet/certificates


%changelog
* Thu May 9 2019 orignal <dotnetorignal@yandex.ru> - 2.25.0
- update to 2.25.0

* Thu Mar 21 2019 orignal <dotnetorignal@yandex.ru> - 2.24.0
- update to 2.24.0

* Mon Jan 21 2019 orignal <dotnetorignal@yandex.ru> - 2.23.0
- update to 2.23.0

* Fri Nov 09 2018 r4sas <r4sas@dotnetmail.org> - 2.22.0
- update to 2.22.0
- add support of tunnelsdir option

* Thu Oct 22 2018 orignal <dotnetorignal@yandex.ru> - 2.21.1
- update to 2.21.1

* Thu Oct 4 2018 orignal <dotnetorignal@yandex.ru> - 2.21.0
- update to 2.21.0

* Thu Aug 23 2018 orignal <dotnetorignal@yandex.ru> - 2.20.0
- update to 2.20.0

* Tue Jun 26 2018 orignal <dotnetorignal@yandex.ru> - 2.19.0
- update to 2.19.0

* Mon Feb 05 2018 r4sas <r4sas@dotnetmail.org> - 2.18.0-2
- Fixed blocking system shutdown for 10 minutes (#1089)

* Thu Feb 01 2018 r4sas <r4sas@dotnetmail.org> - 2.18.0-1
- Added to conflicts dotnet-git package
- Fixed release versioning
- Fixed paths with double slashes

* Tue Jan 30 2018 orignal <dotnetorignal@yandex.ru> - 2.18.0
- update to 2.18.0

* Sat Jan 27 2018 l-n-s <supervillain@riseup.net> - 2.17.0-1
- Added certificates and default configuration files
- Merge dotnet with dotnet-systemd package
- Fixed package changelogs to comply with guidelines

* Mon Dec 04 2017 orignal <dotnetorignal@yandex.ru> - 2.17.0
- update to 2.17.0

* Mon Nov 13 2017 orignal <dotnetorignal@yandex.ru> - 2.16.0
- update to 2.16.0

* Thu Aug 17 2017 orignal <dotnetorignal@yandex.ru> - 2.15.0
- update to 2.15.0

* Thu Jun 01 2017 orignal <dotnetorignal@yandex.ru> - 2.14.0
- update to 2.14.0

* Thu Apr 06 2017 orignal <dotnetorignal@yandex.ru> - 2.13.0
- update to 2.13.0

* Tue Feb 14 2017 orignal <dotnetorignal@yandex.ru> - 2.12.0
- update to 2.12.0

* Mon Dec 19 2016 orignal <dotnetorignal@yandex.ru> - 2.11.0
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
- remove wrong rpath from dotnet binary
- add daemon subpackage with systemd unit file

* Sat May 21 2016 Oleg Girko <ol@infoserver.lv> - 2.7.0-1
- update to 2.7.0

* Tue Apr 05 2016 Oleg Girko <ol@infoserver.lv> - 2.6.0-1
- update to 2.6.0

* Tue Jan 26 2016 Yaroslav Sidlovsky <zawertun@gmail.com> - 2.3.0-1
- initial package for version 2.3.0
