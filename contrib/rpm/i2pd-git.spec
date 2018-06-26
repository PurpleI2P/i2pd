%define git_hash %(git rev-parse HEAD | cut -c -7)

Name:           i2pd-git
Version:        2.19.0
Release:        git%{git_hash}%{?dist}
Summary:        I2P router written in C++
Conflicts:      i2pd

License:        BSD
URL:            https://github.com/PurpleI2P/i2pd
Source0:        https://github.com/PurpleI2P/i2pd/archive/openssl/i2pd-openssl.tar.gz

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
* Thu Feb 01 2018 r4sas <r4sas@i2pmail.org> - 2.18.0
- Initial i2pd-git based on i2pd 2.18.0-1 spec
