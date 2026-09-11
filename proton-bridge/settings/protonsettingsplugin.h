#pragma once

#include <QObject>
#include <QtQml>

// QML extension for the Proton account settings page
// (ui/proton-settings.qml, `import Proton 1.0`). Exposes Explicit,
// user-confirmed deletion of synced data; the scheduled/headless sync
// path never deletes.
class ProtonDataPurger : public QObject
{
    Q_OBJECT
public:
    explicit ProtonDataPurger(QObject *parent = nullptr);

    // Deletes the QContactCollection (contacts go with it) and all mKCal
    // notebooks (with their incidences) owned by the given account id.
    // Returns true when every step succeeded (best-effort per item).
    Q_INVOKABLE bool purgeData(int accountId);
};

class ProtonSettingsPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID QQmlExtensionInterface_iid)
public:
    void registerTypes(const char *uri) override;
    // Installs our .qm translator (if any matches the system locale) so
    // qsTr() in the account QML agents renders translated. Runs in the
    // Settings app process, where per-app auto-loading does NOT apply —
    // hence explicit install here rather than relying on it.
    void initializeEngine(QQmlEngine *engine, const char *uri) override;
};
