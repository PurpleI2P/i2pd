Name:           i2pd
Version:        2.10.0
Release:        3%{?dist}
Summary:        I2P router written in C++

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

%description
C++ implementation of I2P.


%package systemd
Summary:        Files to run I2P router under systemd
Requires:	i2pd
Requires:	systemd
Requires(pre):  %{_sbindir}/useradd %{_sbindir}/groupadd
Obsoletes:      %{name}-daemon


%description systemd
C++ implementation of I2P.

This package contains systemd unit file to run i2pd as a system service
using dedicated user's permissions.


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
install -D -m 755 i2pd %{buildroot}%{_bindir}/i2pd
install -D -m 644 %{_builddir}/%{name}-%{version}/contrib/rpm/i2pd.service %{buildroot}/%{_unitdir}/i2pd.service
install -d -m 700 %{buildroot}/%{_sharedstatedir}/i2pd


%pre systemd
getent group i2pd >/dev/null || %{_sbindir}/groupadd -r i2pd
getent passwd i2pd >/dev/null || \
  %{_sbindir}/useradd -r -g i2pd -s %{_sbindir}/nologin \
                      -d %{_sharedstatedir}/i2pd -c 'I2P Service' i2pd


%post systemd
%systemd_post i2pd.service


%preun systemd
%systemd_preun i2pd.service


%postun systemd
%systemd_postun_with_restart i2pd.service


%files
%doc LICENSE README.md
%_bindir/i2pd


%files systemd
/%_unitdir/i2pd.service
%dir %attr(0700,i2pd,i2pd) %_sharedstatedir/i2pd


%changelog
* Tue Oct 20 2016 Anatolii Vorona <vorona.tolik@gmail.com> - 2.10.0-3
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
