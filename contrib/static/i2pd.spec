%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
# xz payload and sha256 digests: readable by rpm 4.11 (CentOS 7) and newer
%define _binary_payload w9.xzdio
%define _source_payload w9.xzdio
%define _binary_filedigest_algorithm 8
%define _source_filedigest_algorithm 8

Name:           i2pd
Version:        %{ver}
Release:        %{rel}
Summary:        I2P router written in C++ (static build)
License:        BSD-3-Clause
URL:            https://i2pd.website/
Source0:        i2pd-%{_target_cpu}
Requires(pre):  /usr/sbin/useradd
Requires(pre):  /usr/sbin/groupadd
Requires(pre):  /usr/bin/getent

%description
I2P router written in C++. Fully static binary (musl, bundled OpenSSL,
Boost, zlib and miniupnpc) that does not depend on the distribution release.

%prep
%build

%install
S=%{srcdir}
install -D -m 755 %{SOURCE0} %{buildroot}/usr/bin/i2pd
install -d -m 755 %{buildroot}/usr/share/i2pd
install -d -m 700 %{buildroot}/var/lib/i2pd
install -d -m 700 %{buildroot}/var/log/i2pd
install -D -m 644 $S/contrib/i2pd.conf %{buildroot}/etc/i2pd/i2pd.conf
install -D -m 644 $S/contrib/subscriptions.txt %{buildroot}/etc/i2pd/subscriptions.txt
install -D -m 644 $S/contrib/tunnels.conf %{buildroot}/etc/i2pd/tunnels.conf
install -D -m 644 $S/contrib/tunnels.d/README %{buildroot}/etc/i2pd/tunnels.conf.d/README
install -D -m 644 $S/contrib/i2pd.logrotate %{buildroot}/etc/logrotate.d/i2pd
install -D -m 644 $S/contrib/i2pd.service %{buildroot}/usr/lib/systemd/system/i2pd.service
install -D -m 644 $S/debian/i2pd.1 %{buildroot}/usr/share/man/man1/i2pd.1
install -D -m 644 $S/LICENSE %{buildroot}/usr/share/licenses/i2pd/LICENSE
cp -r $S/contrib/certificates %{buildroot}/usr/share/i2pd/certificates
ln -s /usr/share/i2pd/certificates %{buildroot}/var/lib/i2pd/certificates

%pre
getent group i2pd >/dev/null || groupadd -r i2pd
getent passwd i2pd >/dev/null || \
  useradd -r -g i2pd -s /sbin/nologin -d /var/lib/i2pd -c 'I2P Service' i2pd
exit 0

%post
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ]; then
  systemctl preset i2pd.service >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ]; then
  systemctl --no-reload disable --now i2pd.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
  systemctl try-restart i2pd.service >/dev/null 2>&1 || :
fi

%files
%license /usr/share/licenses/i2pd/LICENSE
/usr/bin/i2pd
%dir /etc/i2pd
%config(noreplace) /etc/i2pd/i2pd.conf
%config(noreplace) /etc/i2pd/tunnels.conf
%config(noreplace) /etc/i2pd/subscriptions.txt
%dir /etc/i2pd/tunnels.conf.d
%doc /etc/i2pd/tunnels.conf.d/README
%config(noreplace) /etc/logrotate.d/i2pd
/usr/lib/systemd/system/i2pd.service
/usr/share/man/man1/i2pd.1*
/usr/share/i2pd
%dir %attr(0700,i2pd,i2pd) /var/lib/i2pd
/var/lib/i2pd/certificates
%dir %attr(0700,i2pd,i2pd) /var/log/i2pd

