Name:           endpoint-agent
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Endpoint Platform agent bootstrap bundle
License:        Proprietary
Group:          System/Monitoring
BuildArch:      x86_64
AutoReq:        no
# The release manifest attests every frozen onedir byte.  ALT's brp policy
# strips embedded ELF files after %install, which would invalidate that record.
%global __os_install_post %{nil}
Source0:        endpoint-agent-%{version}.tar.gz

%description
Offline bootstrap bundle for the Endpoint Platform agent. The package contains
no endpoint configuration or enrollment secrets. Provisioning is an explicit
operator action after installation.

%prep
%setup -q

%build

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_libdir}/endpoint-agent
cp -a agent-bundle %{buildroot}%{_libdir}/endpoint-agent/release-bundle
cp -a provision %{buildroot}%{_libdir}/endpoint-agent/provision
chmod 0755 %{buildroot}%{_libdir}/endpoint-agent/provision/install-endpoint-agent.sh
chmod 0755 %{buildroot}%{_libdir}/endpoint-agent/provision/apply-pending-alt-update.sh
chmod 0755 %{buildroot}%{_libdir}/endpoint-agent/provision/rpm-auto-provision.sh
install -m 0755 provision/apply-pending-alt-update.sh \
    %{buildroot}%{_libdir}/endpoint-agent/apply-pending-alt-update
install -d %{buildroot}%{_datadir}/doc/endpoint-agent
install -m 0644 docs/ALT_AGENT_INSTALL.md \
    %{buildroot}%{_datadir}/doc/endpoint-agent/ALT_AGENT_INSTALL.md

%pre
if [ "$1" -eq 1 ]; then
    bootstrap_root=/etc/endpoint-agent/bootstrap
    for parent in /etc /etc/endpoint-agent "$bootstrap_root"; do
        [ -d "$parent" ] && [ ! -L "$parent" ] || exit 1
        [ "$(stat -c %u -- "$parent")" = 0 ] || exit 1
        [ "$(stat -c %g -- "$parent")" = 0 ] || exit 1
    done
    [ "$(stat -c %a -- "$bootstrap_root")" = 700 ] || exit 1
    for input in installation-id ca.crt provisioning-claim; do
        path="$bootstrap_root/$input"
        [ -f "$path" ] && [ ! -L "$path" ] || exit 1
        [ "$(stat -c %u -- "$path")" = 0 ] || exit 1
        [ "$(stat -c %g -- "$path")" = 0 ] || exit 1
        [ "$(stat -c %a -- "$path")" = 600 ] || exit 1
    done
fi

%post
if ! getent passwd endpoint-agent >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin endpoint-agent || :
fi
install -d -o root -g root -m 0755 /etc/endpoint-agent
install -d -o endpoint-agent -g endpoint-agent -m 0750 /var/lib/endpoint-agent
install -d -o endpoint-agent -g endpoint-agent -m 0750 /var/log/endpoint-agent
if [ "$1" -eq 1 ]; then
    if ! %{_libdir}/endpoint-agent/provision/rpm-auto-provision.sh; then
        systemctl disable --now endpoint-agent.service endpoint-agent-update.path endpoint-agent-finalize.path >/dev/null 2>&1 || :
        exit 1
    fi
fi

%files
%defattr(-,root,root,-)
%{_libdir}/endpoint-agent
%doc %{_datadir}/doc/endpoint-agent/ALT_AGENT_INSTALL.md

%changelog
* Tue Aug 11 2026 Endpoint Platform <endpoint@sosnadmin.local> - %{version}-%{release}
- Initial ALT Linux offline agent bootstrap package
