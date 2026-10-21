# The prebuilt payload is already covered by the release manifest.
%global __find_debuginfo_files %{nil}
%define debug_package %{nil}
%def_without user_sensor

Name: endpoint-agent
Version: %{agent_version}
Release: alt5
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
Source20: endpoint-agent.tmpfiles
Source21: endpoint-agent.logrotate
%if_with user_sensor
Source30: endpoint-kde-probe
Source31: foreground.js
Source32: start-user-sensor.py
Source33: endpoint-user-sensor.service
Source34: endpoint-user-sensor.desktop
Source40: extension-id.txt
Source41: start-browser-bridge.py
Source42: browser-native-host.json
Source43: browser-policy-helper.py
Source44: endpoint-agent-browser-policy.service
Source45: browser_policy_protocol.py
Source46: browser_policy.py
Source47: seqpacket.py
Source48: browser_policy_helper.py
%endif
BuildArch: x86_64
BuildRequires: rpm-build-python3
%add_python3_path /usr/lib/endpoint-agent/policy-helper
Requires(pre): shadow-utils
Requires: python3
Requires: systemd

%if_with user_sensor
%package user-sensor
Summary: Unprivileged KDE session sensor for Endpoint Platform
Group: System/Monitoring
Requires: endpoint-agent = %{version}-%{release}

%description user-sensor
Optional per-user KDE Plasma 6 idle/foreground adapter. Uses the existing local
sensor contract and never receives a device credential or opens a server
connection. Qt and KDE dependencies belong only to this optional package.
%endif

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
    %buildroot/usr/share/doc/endpoint-agent/artifact.manifest.json
install -m 0755 %{SOURCE2} %buildroot/opt/endpoint-agent/launcher
install -m 0644 %{SOURCE10} %buildroot/usr/lib/systemd/system/endpoint-agent.service
install -m 0644 %{SOURCE11} %buildroot/usr/lib/systemd/system/endpoint-agent-update.service
install -m 0644 %{SOURCE12} %buildroot/usr/lib/systemd/system/endpoint-agent-update.path
install -m 0755 %{SOURCE13} %buildroot/usr/lib/endpoint-agent/apply-pending-alt-update
install -m 0755 %{SOURCE14} %buildroot/usr/lib/endpoint-agent/check-start-prerequisites
install -m 0755 %{SOURCE15} %buildroot/usr/lib/endpoint-agent/start-endpoint-agent
install -m 0644 %{SOURCE20} %buildroot/usr/lib/tmpfiles.d/endpoint-agent.conf
install -m 0644 %{SOURCE21} %buildroot/etc/logrotate.d/endpoint-agent
install -m 0644 %{_sourcedir}/README.md %buildroot/usr/share/doc/endpoint-agent/README.md
%if_with user_sensor
install -d -m 0755 %buildroot/usr/share/endpoint-agent \
    %buildroot/usr/lib/systemd/user %buildroot/etc/xdg/autostart
install -m 0755 %{SOURCE30} %buildroot/usr/lib/endpoint-agent/endpoint-kde-probe
install -m 0644 %{SOURCE31} %buildroot/usr/share/endpoint-agent/foreground.js
install -m 0755 %{SOURCE32} %buildroot/usr/lib/endpoint-agent/start-user-sensor
install -m 0644 %{SOURCE33} %buildroot/usr/lib/systemd/user/endpoint-user-sensor.service
install -m 0644 %{SOURCE34} %buildroot/etc/xdg/autostart/endpoint-user-sensor.desktop
install -m 0644 %{SOURCE40} %buildroot/usr/share/endpoint-agent/extension-id.txt
install -m 0755 %{SOURCE41} %buildroot/usr/lib/endpoint-agent/browser-bridge
install -m 0755 %{SOURCE43} %buildroot/usr/lib/endpoint-agent/browser-policy-helper
install -m 0644 %{SOURCE44} %buildroot/usr/lib/systemd/system/endpoint-agent-browser-policy.service
install -d -m 0755 %buildroot/etc/chromium/native-messaging-hosts \
    %buildroot/etc/opt/chrome/native-messaging-hosts \
    %buildroot/usr/lib/endpoint-agent/policy-helper/pc_agent/platform/linux
for product in chromium opt/chrome; do
    install -m 0644 %{SOURCE42} %buildroot/etc/$product/native-messaging-hosts/ru.sosnadmin.endpoint.browser.json
done
for package in pc_agent pc_agent/platform pc_agent/platform/linux; do
    install -m 0644 /dev/null %buildroot/usr/lib/endpoint-agent/policy-helper/$package/__init__.py
done
install -m 0644 %{SOURCE45} %buildroot/usr/lib/endpoint-agent/policy-helper/pc_agent/browser_policy_protocol.py
install -m 0644 %{SOURCE46} %buildroot/usr/lib/endpoint-agent/policy-helper/pc_agent/platform/linux/browser_policy.py
install -m 0644 %{SOURCE47} %buildroot/usr/lib/endpoint-agent/policy-helper/pc_agent/platform/linux/seqpacket.py
install -m 0644 %{SOURCE48} %buildroot/usr/lib/endpoint-agent/policy-helper/pc_agent/platform/linux/browser_policy_helper.py
%endif
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
systemctl restart endpoint-agent-update.path || exit 1

%preun
if [ "$1" -eq 0 ]; then
    systemctl disable --now endpoint-agent.service || :
    systemctl disable --now endpoint-agent-update.path || :
fi

%postun
systemctl daemon-reload || :

%if_with user_sensor
%post user-sensor
/usr/lib/endpoint-agent/browser-policy-helper --prepare-directories || exit 1
systemctl daemon-reload || exit 1
systemctl enable --now endpoint-agent-browser-policy.service || exit 1
systemctl try-restart endpoint-agent-browser-policy.service || exit 1
systemctl try-restart endpoint-agent.service || exit 1

%preun user-sensor
if [ "$1" -eq 0 ]; then
    systemctl disable --now endpoint-agent-browser-policy.service || :
    /usr/lib/endpoint-agent/browser-policy-helper --relinquish || :
fi

%postun user-sensor
systemctl daemon-reload || :
%endif

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
/usr/share/doc/endpoint-agent/artifact.manifest.json
%dir /usr/lib/endpoint-agent
%dir /usr/lib/endpoint-agent/package-releases
/usr/lib/endpoint-agent/package-releases/%{version}
/usr/lib/endpoint-agent/current.json.initial
/usr/lib/endpoint-agent/apply-pending-alt-update
/usr/lib/endpoint-agent/check-start-prerequisites
/usr/lib/endpoint-agent/start-endpoint-agent
/usr/lib/systemd/system/endpoint-agent.service
/usr/lib/systemd/system/endpoint-agent-update.service
/usr/lib/systemd/system/endpoint-agent-update.path
/usr/lib/tmpfiles.d/endpoint-agent.conf
%config /etc/logrotate.d/endpoint-agent

%if_with user_sensor
%files user-sensor
/usr/lib/endpoint-agent/endpoint-kde-probe
/usr/lib/endpoint-agent/start-user-sensor
%dir /usr/share/endpoint-agent
/usr/share/endpoint-agent/foreground.js
/usr/lib/systemd/user/endpoint-user-sensor.service
/etc/xdg/autostart/endpoint-user-sensor.desktop
/usr/share/endpoint-agent/extension-id.txt
/usr/lib/endpoint-agent/browser-bridge
/usr/lib/endpoint-agent/browser-policy-helper
/usr/lib/endpoint-agent/policy-helper
/usr/lib/systemd/system/endpoint-agent-browser-policy.service
%dir /etc/chromium/native-messaging-hosts
%dir /etc/opt/chrome/native-messaging-hosts
%config(noreplace) /etc/chromium/native-messaging-hosts/ru.sosnadmin.endpoint.browser.json
%config(noreplace) /etc/opt/chrome/native-messaging-hosts/ru.sosnadmin.endpoint.browser.json
%endif

%changelog
* Wed Oct 21 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.2.125-alt5
- Bound journal diagnostics and preserve update outcome ordering after rollback.

* Wed Oct 21 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.2.124-alt5
- Activate the pending update watcher without requiring a machine reboot.
- Keep the external artifact manifest outside the immutable OTA release tree.

* Wed Oct 21 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.2.123-alt4
- Add optional KDE/Chromium user sensors and restricted browser policy helper.
- Preserve headless Core credentials and existing corporate browser policy.

* Fri Sep 04 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.2.37-alt3
- Publish the legacy-cutover headless agent as an upgrade over the canary baseline.

* Sun Aug 02 2026 Endpoint Platform Maintainers <endpoint@example.invalid> 3.1.76-alt1
- Initial native ALT package for the headless WSS agent.
