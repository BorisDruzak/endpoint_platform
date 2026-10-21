// Only KWin's active process ID crosses this user-session D-Bus boundary.
// Never read captions, resource names, URLs, paths, or window contents.
function report() {
    const window = workspace.activeWindow;
    callDBus("org.endpointplatform.UserSensor", "/Sensor",
             "org.endpointplatform.UserSensor", "Foreground", window ? window.pid : 0);
}
workspace.windowActivated.connect(report);
report();
