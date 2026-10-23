// Optional per-user KDE adapter. System Core never loads Qt or opens a display.
#include <KIdleTime>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusContext>
#include <QDBusInterface>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusReply>
#include <QDBusServiceWatcher>
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QSocketNotifier>
#include <QScreen>
#include <cstdio>
#include <unistd.h>

static const QString service = QStringLiteral("org.endpointplatform.UserSensor");
static const QString plugin = QStringLiteral("endpoint-platform-foreground");

class Probe : public QObject, protected QDBusContext {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.endpointplatform.UserSensor")
public:
    bool start() {
        auto bus = QDBusConnection::sessionBus();
        if (!bus.isConnected() || !bus.registerService(service)
            || !bus.registerObject(QStringLiteral("/Sensor"), this, QDBusConnection::ExportAllSlots)) {
            return false;
        }
        m_idle = KIdleTime::instance();
        m_idleAvailable = m_idle->addIdleTimeout(1000) != 0;
        connect(m_idle, &KIdleTime::timeoutReached, this, [this](int, int) { m_isIdle = true; });
        connect(m_idle, &KIdleTime::resumingFromIdle, this, [this] {
            m_knownInput = true;
            m_isIdle = false;
            m_sinceInput.restart();
            QTimer::singleShot(0, m_idle, &KIdleTime::catchNextResumeEvent);
        });
        m_idle->catchNextResumeEvent();
        loadScript();
        auto kwinWatcher = new QDBusServiceWatcher(QStringLiteral("org.kde.KWin"), bus,
            QDBusServiceWatcher::WatchForOwnerChange, this);
        connect(kwinWatcher, &QDBusServiceWatcher::serviceOwnerChanged, this,
            [this](const QString &, const QString &, const QString &next) {
                m_pid = 0;
                m_scriptLoaded = false;
                if (!next.isEmpty()) QTimer::singleShot(0, this, &Probe::loadScript);
            });
        connect(&m_timer, &QTimer::timeout, this, &Probe::sample);
        m_timer.start(5000);
        QTimer::singleShot(0, this, &Probe::sample);
        return true;
    }
    ~Probe() override {
        if (m_scriptLoaded) {
            auto call = QDBusMessage::createMethodCall(QStringLiteral("org.kde.KWin"), QStringLiteral("/Scripting"),
                                                      QStringLiteral("org.kde.kwin.Scripting"), QStringLiteral("unloadScript"));
            call << plugin;
            QDBusConnection::sessionBus().call(call, QDBus::Block, 1000);
        }
    }
public slots:
    void Foreground(int pid) {
        if (!calledFromDBus()) return;
        const auto owner = QDBusConnection::sessionBus().interface()->serviceOwner(QStringLiteral("org.kde.KWin"));
        if (!owner.isValid() || message().service() != owner.value()) {
            sendErrorReply(QDBusError::AccessDenied, QStringLiteral("KWIN_REQUIRED"));
            return;
        }
        m_pid = pid > 0 ? pid : 0;
    }
private:
    void loadScript() {
        auto bus = QDBusConnection::sessionBus();
        auto call = QDBusMessage::createMethodCall(QStringLiteral("org.kde.KWin"), QStringLiteral("/Scripting"),
                                                  QStringLiteral("org.kde.kwin.Scripting"), QStringLiteral("unloadScript"));
        call << plugin;
        bus.call(call, QDBus::Block, 1000); // Only our ephemeral script; no KWin configuration is changed.
        call = QDBusMessage::createMethodCall(QStringLiteral("org.kde.KWin"), QStringLiteral("/Scripting"),
                                              QStringLiteral("org.kde.kwin.Scripting"), QStringLiteral("loadScript"));
        call.setArguments({QStringLiteral("/usr/share/endpoint-agent/foreground.js"), plugin});
        const QDBusReply<int> loaded = bus.call(call, QDBus::Block, 1000);
        if (!loaded.isValid() || loaded.value() < 0) return;
        m_scriptLoaded = true;
        const auto run = QDBusMessage::createMethodCall(QStringLiteral("org.kde.KWin"),
            QStringLiteral("/Scripting/Script%1").arg(loaded.value()), QStringLiteral("org.kde.kwin.Script"), QStringLiteral("run"));
        bus.call(run, QDBus::Block, 1000);
    }
    void sample() {
        if (m_pending) return;
        m_pending = true;
        auto call = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.ScreenSaver"), QStringLiteral("/ScreenSaver"),
            QStringLiteral("org.freedesktop.ScreenSaver"), QStringLiteral("GetActive"));
        auto watcher = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(call, 1000), this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher] {
            const QDBusPendingReply<bool> lockReply = *watcher;
            QJsonValue idle(QJsonValue::Null);
            bool outputAvailable = false;
            for (const auto screen : QGuiApplication::screens()) {
                if (!screen->name().isEmpty() && !screen->geometry().isEmpty()) outputAvailable = true;
            }
            if (m_idleAvailable && outputAvailable) {
                if (QGuiApplication::platformName() == QStringLiteral("xcb")) {
                    const int value = m_idle->idleTime();
                    if (value >= 0) idle = value;
                } else if (m_knownInput) {
                    // Wayland KIdleTime cannot poll elapsed idle. Resume and
                    // threshold events establish this clock after real input.
                    idle = m_isIdle ? QJsonValue(m_sinceInput.elapsed()) : QJsonValue(0);
                }
            }
            QJsonObject result{{"probe_v", 1}, {"idle_ms", idle},
                {"locked", lockReply.isValid() ? QJsonValue(lockReply.value()) : QJsonValue(QJsonValue::Null)},
                {"pid", outputAvailable && m_pid > 0 ? QJsonValue(m_pid) : QJsonValue(QJsonValue::Null)},
                {"backend", QGuiApplication::platformName()}};
            const QByteArray line = QJsonDocument(result).toJson(QJsonDocument::Compact);
            std::fwrite(line.constData(), 1, size_t(line.size()), stdout);
            std::fputc('\n', stdout);
            std::fflush(stdout);
            watcher->deleteLater();
            m_pending = false;
        });
    }
    QTimer m_timer;
    KIdleTime *m_idle = nullptr;
    QElapsedTimer m_sinceInput;
    bool m_idleAvailable = false, m_knownInput = false, m_isIdle = false;
    bool m_pending = false, m_scriptLoaded = false;
    int m_pid = 0;
};

int main(int argc, char **argv) {
    if (getuid() == 0 || geteuid() != getuid()) return 1;
    QGuiApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    const auto platform = QGuiApplication::platformName();
    if (platform != QStringLiteral("xcb") && platform != QStringLiteral("wayland")) return 1;
    Probe probe;
    if (!probe.start()) return 1;
    QSocketNotifier stdinWatcher(STDIN_FILENO, QSocketNotifier::Read);
    stdinWatcher.setEnabled(app.arguments().contains(QStringLiteral("--managed-stdin")));
    QObject::connect(&stdinWatcher, &QSocketNotifier::activated, &app, [&app] { app.quit(); });
    return app.exec();
}

#include "main.moc"
