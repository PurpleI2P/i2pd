%define git_hash %(git rev-parse HEAD | cut -c -7)

Name:           dotnet-git
Version:        2.25.0
Release:        git%{git_hash}%{?dist}
Summary:        DOTNET router written in C++
Conflicts:      dotnet

License:        BSD
URL:            https://github.com/PurpleI2P/dotnet
Source0:        https://github.com/PurpleI2P/dotnet/archive/openssl/dotnet-openssl.tar.gz

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
%{__install} -D -m 755 dotnet %{buildroot}%{_sbindir}/dotnet
%{__install} -D -m 755 %{_builddir}/%{name}-%{version}/contrib/dotnet.conf %{buildroot}%{_sysconfdir}/dotnet/dotnet.conf
%{__install} -D -m 755 %{_builddir}/%{name}-%{version}/contrib/subscriptions.txt %{buildroot}%{_sysconfdir}/dotnet/subscriptions.txt
%{__install} -D -m 755 %{_builddir}/%{name}-%{version}/contrib/tunnels.conf %{buildroot}%{_sysconfdir}/dotnet/tunnels.conf
%{__install} -D -m 755 %{_builddir}/%{name}-%{version}/contrib/tunnels.d/README %{buildroot}%{_sysconfdir}/dotnet/tunnels.conf.d/README
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/contrib/rpm/dotnet.service %{buildroot}%{_unitdir}/dotnet.service
%{__install} -D -m 644 %{_builddir}/%{name}-%{version}/debian/dotnet.1 %{buildroot}%{_mandir}/man1/dotnet.1
%{__install} -d -m 700 %{buildroot}%{_sharedstatedir}/dotnet
%{__install} -d -m 700 %{buildroot}%{_localstatedir}/log/dotnet
%{__install} -d -m 755 %{buildroot}%{_datadir}/%{name}
%{__cp} -r %{_builddir}/%{name}-%{version}/contrib/certificates/ %{buildroot}%{_datadir}/%{name}/certificates
ln -s %{_datadir}/%{name}/certificates %{buildroot}%{_sharedstatedir}/dotnet/certificates


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
%doc LICENSE README.md contrib/dotnet.conf contrib/subscriptions.txt contrib/tunnels.conf contrib/tunnels.d
%{_sbindir}/dotnet
%config(noreplace) %{_sysconfdir}/dotnet/*
%{_unitdir}/dotnet.service
%{_mandir}/man1/dotnet.1*
%dir %attr(0700,dotnet,dotnet) %{_sharedstatedir}/dotnet
%dir %attr(0700,dotnet,dotnet) %{_localstatedir}/log/dotnet
%{_datadir}/%{name}/certificates
%{_sharedstatedir}/dotnet/certificates


%changelog
* Thu May 9 2019 orignal <dotnetorignal@yandex.ru> - 2.25.0
- update to 2.25.0

* Thu Mar 21 2019 orignal <dotnetorignal@yandex.ru> - 2.24.0
- update to 2.24.0

* Mon Jan 21 2019 orignal <dotnetorignal@yandex.ru> - 2.23.0
- update to 2.23.0

* Fri Nov 09 2018 r4sas <r4sas@dotnetmail.org> - 2.22.0
- add support of tunnelsdir option

* Thu Feb 01 2018 r4sas <r4sas@dotnetmail.org> - 2.18.0
- Initial dotnet-git based on dotnet 2.18.0-1 spec
