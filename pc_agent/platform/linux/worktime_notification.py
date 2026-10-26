"""Native freedesktop DBus notification through libnotify in the KDE session."""
import os
import subprocess


def notify():
    if os.getuid() == 0 or os.geteuid() != os.getuid() or not os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
        raise OSError('Graphical user session required')
    try:
        result = subprocess.run(['/usr/bin/notify-send', '--app-name=Endpoint Agent',
            '--action=reason=Указать причину', '--action=later=Позже', '--wait', '--expire-time=45000',
            'Рабочее время', 'После возвращения за компьютер нужно пояснить период отсутствия.'],
            capture_output=True, text=True, timeout=50, check=False)
        action = result.stdout.strip()
        if result.returncode != 0:
            raise OSError('Native notification unavailable')
        return action if action in {'reason', 'later'} else None
    except subprocess.TimeoutExpired:
        # A notification server can retain a notice after ignoring expire-time;
        # the wait deadline must not turn that into a second user notice.
        return None
    except OSError:
        raise OSError('Native notification unavailable') from None
