#pragma once

#include "Buteo/ClientPlugin.h"
#include "Buteo/SyncPluginLoader.h"

#include <QContactManager>
#include <QContact>
#include <QContactDetail>
#include <QContactName>
#include <QContactPhoneNumber>
#include <QContactEmailAddress>
#include <QContactAddress>
#include <QContactOrganization>
#include <QContactNote>
#include <QContactAvatar>
#include <QContactCollection>
#include <QContactCollectionId>
#include <QContactGuid>
#include <QContactTimestamp>
#include <QContactSyncTarget>
#include <QContactDisplayLabel>
#include <QContactDetailFilter>
#include <QContactCollectionFilter>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>
#include <QSettings>

#include <QContactBirthday>
#include <QContactNickname>
#include <QContactUrl>
#include <QContactGender>
#include <QContactAnniversary>
#include <QOrganizerManager>
#include <QOrganizerEvent>
#include <QOrganizerItemId>

#include <Accounts/manager.h>
#include <Accounts/account.h>
#include <Accounts/account-service.h>
#include <Accounts/auth-data.h>
#include <Accounts/service.h>
#include <SignOn/identity.h>
#include <SignOn/identityinfo.h>
#include <SignOn/authsession.h>
#include <SignOn/sessiondata.h>
#include <SignOn/signonerror.h>

#include "proton_bridge.h"

namespace Proton {

class ProtonContactsPlugin : public Buteo::ClientPlugin
{
    Q_OBJECT

public:
    ProtonContactsPlugin(const QString &aPluginName,
                         const Buteo::SyncProfile &aProfile,
                         Buteo::PluginCbInterface *aCbInterface);
    ~ProtonContactsPlugin() override;

    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus aStatus = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;

public slots:
    void connectivityStateChanged(Sync::ConnectivityType aType, bool aState) override;

private slots:
    void pollStatus();
    void onSignOnResponse(const SignOn::SessionData &data);
    void onSignOnError(const SignOn::Error &error);

private:
    bool requestCredentials();
    bool writeContactsToQtPIM(const QByteArray &json);
    QtContacts::QContactCollection findOrCreateCollection();
    void persistTokens(const QString &refreshToken, const QString &uid);
    QPair<QString, QString> loadPersistedTokens();

    ProtonSyncEngine *m_engine = nullptr;
    QTimer *m_timer = nullptr;
    QtContacts::QContactManager *m_manager = nullptr;
    QString m_accountId;
    Accounts::Manager *m_accountManager = nullptr;
    Accounts::AccountService *m_accountService = nullptr;
    SignOn::Identity *m_identity = nullptr;
    SignOn::AuthSession *m_authSession = nullptr;
    bool m_credentialsReady = false;
};

class ProtonCalendarPlugin : public Buteo::ClientPlugin
{
    Q_OBJECT
public:
    ProtonCalendarPlugin(const QString &aPluginName,
                         const Buteo::SyncProfile &aProfile,
                         Buteo::PluginCbInterface *aCbInterface);
    ~ProtonCalendarPlugin() override;
    bool init() override;
    bool uninit() override;
    bool startSync() override;
    void abortSync(Sync::SyncStatus aStatus = Sync::SYNC_ABORTED) override;
    bool cleanUp() override;
    Buteo::SyncResults getSyncResults() const override;
public slots:
    void connectivityStateChanged(Sync::ConnectivityType aType, bool aState) override;
private:
    bool m_inited = false;
};

class ProtonPluginLoader : public Buteo::SyncPluginLoader
{
    Q_OBJECT
    Q_INTERFACES(Buteo::SyncPluginLoader)
    Q_PLUGIN_METADATA(IID "com.buteo.msyncd.SyncPluginLoader/1.0")

public:
    Buteo::ClientPlugin *createClientPlugin(const QString &aPluginName,
                                            const Buteo::SyncProfile &aProfile,
                                            Buteo::PluginCbInterface *aCbInterface) override;
};

}
