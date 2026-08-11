%define debug_package %{nil}

Name: endpoint-agent
Version: %{agent_version}
Release: alt1
Summary: Endpoint Platform headless management agent for ALT Linux
License: Proprietary
Group: System/Servers
Url: https://github.com/BorisDruzak/endpoint_platform
Source0: endpoint-agent-linux_amd64-%{version}.tar.gz
Source1: endpoint-agent-linux_amd64-%{version}.manifest.json
Source2: launcher
Source10: endpoint-agent.service
Source11: endpoint-agent-update.service
Source12: endpoint-agent-update.path
Source13: apply-pending-alt-update.sh
Source14: check-start-prerequisites.py
Source15: start-endpoint-agent.py
Source16: endpoint-agent-fingerprint
Source20: endpoint-agent.tmpfiles
Source21: endpoint-agent.logrotate
BuildArch: x86_64
Requires(pre): shadow-utils
Requires: python3
Requires: systemd

%description
The native ALT Linux package for the headless Endpoint Platform agent. Device
configuration, CA trust, enrollment claims, identity, and credentials are
operator or runtime state and are deliberately not part of this RPM.

%prep
%setup -q -c -T
tar -xzf %{SOURCE0}

%build

%install
install -d -m 0755 \
    %buildroot/opt/endpoint-agent/versions/%{version} \
    %buildroot/usr/lib/endpoint-agent \
    %buildroot/usr/lib/endpoint-agent/package-releases \
    %buildroot/usr/lib/systemd/system \
    %buildroot/usr/lib/tmpfiles.d \
    %buildroot/etc/logrotate.d \
    %buildroot/usr/share/doc/endpoint-agent
cp -a endpoint-agent %buildroot/opt/endpoint-agent/versions/%{version}/endpoint-agent
install -m 0644 manifest.json \
    %buildroot/opt/endpoint-agent/versions/%{version}/manifest.json
install -m 0644 %{SOURCE1} \
    %buildroot/opt/endpoint-agent/versions/%{version}/artifact.manifest.json
install -m 0755 %{SOURCE2} %buildroot/opt/endpoint-agent/launcher
install -m 0644 %{SOURCE10} %buildroot/usr/lib/systemd/system/endpoint-agent.service
install -m 0644 %{SOURCE11} %buildroot/usr/lib/systemd/system/endpoint-agent-update.service
install -m 0644 %{SOURCE12} %buildroot/usr/lib/systemd/system/endpoint-agent-update.path
install -m 0755 %{SOURCE13} %buildroot/usr/lib/endpoint-agent/apply-pending-alt-update
install -m 0755 %{SOURCE14} %buildroot/usr/lib/endpoint-agent/check-start-prerequisites
install -m 0755 %{SOURCE15} %buildroot/usr/lib/endpoint-agent/start-endpoint-agent
install -m 0755 %{SOURCE16} %buildroot/usr/lib/endpoint-agent/endpoint-agent-fingerprint
install -m 0644 %{SOURCE20} %buildroot/usr/lib/tmpfiles.d/endpoint-agent.conf
install -m 0644 %{SOURCE21} %buildroot/etc/logrotate.d/endpoint-agent
install -m 0644 %{_sourcedir}/README.md %buildroot/usr/share/doc/endpoint-agent/README.md
install -m 0644 /dev/null \
    %buildroot/usr/lib/endpoint-agent/package-releases/%{version}
printf '{"schema_version":1,"source_revision":"%%s","version":"%%s"}\n' \
    '%{source_revision}' '%{version}' \
    > %buildroot/usr/lib/endpoint-agent/current.json.initial

%pre
if ! getent group endpoint-agent >/dev/null 2>&1; then
    groupadd -r endpoint-agent
fi
if ! getent passwd endpoint-agent >/dev/null 2>&1; then
    useradd -r -g endpoint-agent -d /nonexistent -s /sbin/nologin endpoint-agent
else
    endpoint_agent_entry=$(getent passwd endpoint-agent)
    endpoint_agent_gid=$(getent group endpoint-agent | cut -d: -f3)
    endpoint_agent_user_gid=$(printf '%%s\n' "$endpoint_agent_entry" | cut -d: -f4)
    endpoint_agent_home=$(printf '%%s\n' "$endpoint_agent_entry" | cut -d: -f6)
    endpoint_agent_shell=$(printf '%%s\n' "$endpoint_agent_entry" | cut -d: -f7)
    [ "$endpoint_agent_gid" = "$endpoint_agent_user_gid" ] || exit 1
    [ "$endpoint_agent_home" = /nonexistent ] || exit 1
    case "$endpoint_agent_shell" in
        /sbin/nologin|/usr/sbin/nologin) ;;
        *) exit 1 ;;
    esac
fi

%post
/usr/lib/endpoint-agent/check-start-prerequisites --prepare-directories || exit 1
install_current_selector() {
    selector_stage=$(mktemp /opt/endpoint-agent/.current.json.rpm.XXXXXX) || return 1
    install -o root -g root -m 0644 \
        /usr/lib/endpoint-agent/current.json.initial "$selector_stage" || return 1
    mv -f "$selector_stage" /opt/endpoint-agent/current.json
}
if [ ! -e /opt/endpoint-agent/current.json ] && [ ! -L /opt/endpoint-agent/current.json ]; then
    install_current_selector || exit 1
elif [ "$1" -gt 1 ]; then
    selected_version=$(
        /usr/lib/endpoint-agent/check-start-prerequisites --print-selected-version
    ) || exit 1
    if [ "$selected_version" != '%{version}' ]; then
        if [ -f "/usr/lib/endpoint-agent/package-releases/$selected_version" ]; then
            install_current_selector || exit 1
        fi
    fi
fi
/usr/lib/endpoint-agent/check-start-prerequisites --allow-unconfigured || exit 1
systemctl daemon-reload || exit 1
systemctl enable endpoint-agent.service endpoint-agent-update.path || exit 1
systemctl try-restart endpoint-agent.service || exit 1
systemctl try-restart endpoint-agent-update.path || exit 1

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now endpoint-agent.service || :
    systemctl disable --now endpoint-agent-update.path || :
fi

%postun
systemctl daemon-reload || :

%files
%doc /usr/share/doc/endpoint-agent/README.md
%dir /opt/endpoint-agent
%dir /opt/endpoint-agent/versions
%dir /opt/endpoint-agent/versions/%{version}
%dir /opt/endpoint-agent/versions/%{version}/endpoint-agent
/opt/endpoint-agent/launcher
/opt/endpoint-agent/versions/%{version}/endpoint-agent/endpoint-agent
/opt/endpoint-agent/versions/%{version}/endpoint-agent/_internal
/opt/endpoint-agent/versions/%{version}/manifest.json
/opt/endpoint-agent/versions/%{version}/artifact.manifest.json
%dir /usr/lib/endpoint-agent
%dir /usr/lib/endpoint-agent/package-releases
/usr/lib/endpoint-agent/package-releases/%{version}
/usr/lib/endpoint-agent/current.json.initial
/usr/lib/endpoint-agent/apply-pending-alt-update
/usr/lib/endpoint-agent/check-start-prerequisites
/usr/lib/endpoint-agent/start-endpoint-agent
/usr/lib/endpoint-agent/endpoint-agent-fingerprint
/usr/lib/systemd/system/endpoint-agent.service
/usr/lib/systemd/system/endpoint-agent-update.service
/usr/lib/systemd/system/endpoint-agent-update.path
/usr/lib/tmpfiles.d/endpoint-agent.conf
%config /etc/logrotate.d/endpoint-agent

%changelog
* Sun Aug 02 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.1.76-alt1
- Initial native ALT package for the headless WSS agent.
