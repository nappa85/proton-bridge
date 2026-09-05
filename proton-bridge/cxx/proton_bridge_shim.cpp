#include "proton_bridge_shim.h"
#include <QDebug>
#include <QThread>
#include <QFile>
#include <QDateTime>
#include <QRegularExpression>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>

static void proton_log(const QString &msg) {
    QFile f("/tmp/proton-sync-debug.log");
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        f.write(QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8());
        f.write(" ");
        f.write(msg.toUtf8());
        f.write("\n");
        f.close();
    }
    qDebug() << msg;
}

static void sendProtonNotification(const QString &summary, const QString &body) {
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("/org/freedesktop/Notifications"),
        QStringLiteral("org.freedesktop.Notifications"),
        QStringLiteral("Notify"));
    QVariantList args;
    args << QStringLiteral("proton-contacts") // app_name
         << (uint)0 // replaces_id
         << QStringLiteral("image://theme/icon-m-file-vcard") // app_icon
         << summary
         << body
         << QStringList() // actions
         << QVariantMap() // hints
         << (int)10000; // timeout
    msg.setArguments(args);
    QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
    proton_log(QStringLiteral("Notification: ") + summary + " – " + body);
}

using namespace Proton;

static const QString PROTON_SERVICE_NAME = QStringLiteral("proton-carddav");

ProtonContactsPlugin::ProtonContactsPlugin(const QString &aPluginName,
                                           const Buteo::SyncProfile &aProfile,
                                           Buteo::PluginCbInterface *aCbInterface)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
    , m_manager(new QtContacts::QContactManager(QStringLiteral("org.nemomobile.contacts.sqlite")))
{
    proton_log(QStringLiteral("ProtonContactsPlugin constructed: ") + aPluginName
             + " profileName=" + getProfileName());
}

ProtonContactsPlugin::~ProtonContactsPlugin()
{
    if (m_engine) {
        proton_bridge_destroy_engine(m_engine);
        m_engine = nullptr;
    }
    delete m_manager;
}

bool ProtonContactsPlugin::init()
{
    proton_log(QStringLiteral("ProtonContactsPlugin::init() profileName=") + getProfileName());

    m_accountId = iProfile.key(QStringLiteral("accountid"));
    proton_log(QStringLiteral("accountid from profile: ") + (m_accountId.isEmpty() ? QStringLiteral("(empty)") : m_accountId));

    if (m_accountId.isEmpty()) {
        QString profileName = getProfileName();
        QRegularExpression re("-(\\d+)$");
        QRegularExpressionMatch match = re.match(profileName);
        if (match.hasMatch()) {
            m_accountId = match.captured(1);
            proton_log(QStringLiteral("Extracted accountid from profile name: ") + m_accountId);
        }
    }

    if (m_accountId.isEmpty()) {
        m_accountId = iProfile.key(QStringLiteral("account_id"));
        proton_log(QStringLiteral("Trying account_id: ") + (m_accountId.isEmpty() ? QStringLiteral("(empty)") : m_accountId));
    }

    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: Cannot determine accountid"));
        return false;
    }

    proton_log(QStringLiteral("accountid = ") + m_accountId);

    m_accountManager = new Accounts::Manager(this);
    if (!m_accountManager) {
        proton_log(QStringLiteral("ERROR: Failed to create Accounts::Manager"));
        return false;
    }

    return requestCredentials();
}

bool ProtonContactsPlugin::requestCredentials()
{
    Accounts::AccountId accId = static_cast<Accounts::AccountId>(m_accountId.toUInt());
    proton_log(QStringLiteral("Loading account id=") + QString::number(accId));

    Accounts::Account *account = Accounts::Account::fromId(m_accountManager, accId, this);
    if (!account) {
        proton_log(QStringLiteral("ERROR: Unable to load account ") + m_accountId);
        return false;
    }

    proton_log(QStringLiteral("Account loaded, provider=") + account->providerName());

    Accounts::Service service = m_accountManager->service(PROTON_SERVICE_NAME);
    if (!service.isValid()) {
        proton_log(QStringLiteral("ERROR: Unable to find service ") + PROTON_SERVICE_NAME);
        return false;
    }

    proton_log(QStringLiteral("Service found: ") + service.name());

    account->selectService(service);
    Accounts::AccountService *accountService = new Accounts::AccountService(account, service, this);
    Accounts::AuthData authData = accountService->authData();

    quint32 credentialsId = authData.credentialsId();
    if (credentialsId == 0) {
        // Some creation flows store CredentialsId as int32, which the
        // authData() uint32 getter cannot read. Fall back to the generic
        // settings read (which converts) and heal the stored type.
        account->selectService(service);
        QVariant raw = account->value(QStringLiteral("CredentialsId"));
        if (raw.isValid() && raw.toUInt() > 0) {
            credentialsId = raw.toUInt();
            proton_log(QStringLiteral("Healing CredentialsId (wrong variant type) to ") + QString::number(credentialsId));
            account->setCredentialsId(credentialsId);
            account->sync();
        }
    }
    if (credentialsId == 0) {
        // Last resort: the provider-wide default credentials.
        account->selectService(Accounts::Service());
        credentialsId = account->credentialsId();
        if (credentialsId > 0) {
            proton_log(QStringLiteral("Using account default credentials id ") + QString::number(credentialsId));
            account->selectService(service);
        }
    }

    proton_log(QStringLiteral("credentialsId=") + QString::number(credentialsId)
             + " method=" + authData.method() + " mechanism=" + authData.mechanism());

    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn identity for id=") + QString::number(credentialsId));
        return false;
    }

    m_authSession = m_identity->createSession(authData.method());
    if (!m_authSession) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn auth session"));
        return false;
    }

    connect(m_authSession, &SignOn::AuthSession::response,
            this, &ProtonContactsPlugin::onSignOnResponse);
    connect(m_authSession, &SignOn::AuthSession::error,
            this, &ProtonContactsPlugin::onSignOnError);

    SignOn::SessionData sessionData;
    // The sync plugin must never trigger interactive prompts: tokens were
    // obtained during account creation / credentials update. If they have
    // expired beyond refresh, the sync reports an authentication failure and
    // the user re-enters credentials through the account settings UI.
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());

    proton_log(QStringLiteral("SignOn auth session started (method=%1)").arg(authData.method()));
    return true;
}

void ProtonContactsPlugin::onSignOnResponse(const SignOn::SessionData &data)
{
    proton_log(QStringLiteral("onSignOnResponse()"));

    // Detect locked 2FA session returned via custom TwoFARequired flag (QML OTP flow)
    // or missing scopes. The sync plugin runs with NoUserInteractionPolicy, so it
    // cannot prompt for OTP – the user must update credentials via Settings.
    bool twoFARequired = data.getProperty(QStringLiteral("TwoFARequired")).toBool();
    if (twoFARequired) {
        QString err = QStringLiteral("Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code");
        proton_log(QStringLiteral("2FA required but no UI allowed in sync session"));
        emit error(getProfileName(), err, Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }

    QString username = data.UserName();
    QString password = data.Secret();
    QString accessToken = data.getProperty(QStringLiteral("AccessToken")).toString();
    QString refreshToken = data.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = data.getProperty(QStringLiteral("Uid")).toString();
    QString derivedJson = data.getProperty(QStringLiteral("DerivedPasswords")).toString();

    // Try Secret via Secret() and via getProperty for robustness (signond may strip Secret)
    QString secretViaProperty = data.getProperty(QStringLiteral("Secret")).toString();
    QString passwordViaProperty = data.getProperty(QStringLiteral("Password")).toString();
    QString userNameViaProperty = data.getProperty(QStringLiteral("UserName")).toString();
    if (password.isEmpty() && !secretViaProperty.isEmpty()) password = secretViaProperty;
    if (password.isEmpty() && !passwordViaProperty.isEmpty()) password = passwordViaProperty;
    if (username.isEmpty() && !userNameViaProperty.isEmpty()) username = userNameViaProperty;
    proton_log(QStringLiteral("Got credentials: username=") + username + " (viaProp=" + userNameViaProperty + ")"
             + " pw_len=" + QString::number(password.length()) + " (Secret prop len=" + QString::number(secretViaProperty.length()) + " Password prop len=" + QString::number(passwordViaProperty.length()) + ")"
             + " access_token=" + (accessToken.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)"))
             + " refresh_token=" + (refreshToken.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)"))
             + " uid=" + (uid.isEmpty() ? QStringLiteral("(none)") : uid)
             + " derived=" + (derivedJson.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)")) + " derived_len=" + QString::number(derivedJson.length())
             + " allKeys=" + data.propertyNames().join(","));

    if (refreshToken.isEmpty() || uid.isEmpty()) {
        auto tokens = loadPersistedTokens();
        if (refreshToken.isEmpty()) refreshToken = tokens.first;
        if (uid.isEmpty()) uid = tokens.second;
    }
    if (derivedJson.isEmpty()) {
        QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
        // Try accountId group (legacy)
        settings.beginGroup(m_accountId);
        derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
        settings.endGroup();
        if (!derivedJson.isEmpty()) {
            proton_log(QStringLiteral("Loaded derived passwords from QSettings cache (accountId)"));
        } else if (!uid.isEmpty()) {
            settings.beginGroup(uid);
            derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
            settings.endGroup();
            if (!derivedJson.isEmpty()) {
                proton_log(QStringLiteral("Loaded derived passwords from QSettings cache (Uid)"));
            }
        }
        if (derivedJson.isEmpty() && !username.isEmpty()) {
            settings.beginGroup(username);
            derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
            settings.endGroup();
            if (!derivedJson.isEmpty()) {
                proton_log(QStringLiteral("Loaded derived passwords from QSettings cache (username)"));
            }
        }
    }

    if (accessToken.isEmpty() && refreshToken.isEmpty()) {
        emit error(getProfileName(), QStringLiteral("No auth tokens received"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }

    // If derived passwords are available, password can be empty (derived-only mode)
    // Keep password for first sync to generate derived, afterwards derived will be used
    m_engine = proton_bridge_create_engine_with_derived(
        username.toUtf8().constData(),
        password.toUtf8().constData(),
        accessToken.toUtf8().constData(),
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData(),
        "",
        derivedJson.toUtf8().constData()
    );

    if (!m_engine) {
        emit error(getProfileName(), QStringLiteral("Failed to create sync engine"), Buteo::SyncResults::INTERNAL_ERROR);
        return;
    }

    m_credentialsReady = true;
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &ProtonContactsPlugin::pollStatus);
    if (!startSync()) {
        emit error(getProfileName(), QStringLiteral("Failed to start sync"), Buteo::SyncResults::INTERNAL_ERROR);
    }
}

void ProtonContactsPlugin::onSignOnError(const SignOn::Error &signOnError)
{
    proton_log(QStringLiteral("onSignOnError(): type=") + QString::number(signOnError.type())
             + " msg=" + signOnError.message());
    emit error(getProfileName(), QStringLiteral("Authentication failed: ") + signOnError.message(), Buteo::SyncResults::AUTHENTICATION_FAILURE);
}

bool ProtonContactsPlugin::uninit()
{
    proton_log(QStringLiteral("ProtonContactsPlugin::uninit()"));

    if (m_timer) {
        m_timer->stop();
        delete m_timer;
        m_timer = nullptr;
    }

    if (m_engine) {
        proton_bridge_destroy_engine(m_engine);
        m_engine = nullptr;
    }

    m_credentialsReady = false;
    return true;
}

bool ProtonContactsPlugin::startSync()
{
    proton_log(QStringLiteral("startSync() credentialsReady=") + (m_credentialsReady ? "true" : "false"));

    if (!m_credentialsReady) {
        qDebug() << "ProtonContactsPlugin: credentials not ready yet, will start sync after auth";
        return true;
    }

    if (!m_engine) {
        qWarning() << "Engine not initialized";
        emit error(getProfileName(), QStringLiteral("Engine not initialized"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }

    bool ok = proton_bridge_start_sync(m_engine);
    if (!ok) {
        qWarning() << "Failed to start sync";
        emit error(getProfileName(), QStringLiteral("Failed to start sync"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }

    m_timer->start(500);
    return true;
}

void ProtonContactsPlugin::abortSync(Sync::SyncStatus aStatus)
{
    Q_UNUSED(aStatus);
    qDebug() << "ProtonContactsPlugin::abortSync()";

    if (m_timer) {
        m_timer->stop();
    }

    if (m_engine) {
        proton_bridge_abort_sync(m_engine);
    }
}

bool ProtonContactsPlugin::cleanUp()
{
    qDebug() << "ProtonContactsPlugin::cleanUp()";
    return true;
}

Buteo::SyncResults ProtonContactsPlugin::getSyncResults() const
{
    return Buteo::SyncResults();
}

void ProtonContactsPlugin::connectivityStateChanged(Sync::ConnectivityType aType, bool aState)
{
    Q_UNUSED(aType);
    Q_UNUSED(aState);
}

void ProtonContactsPlugin::pollStatus()
{
    if (!m_engine) {
        return;
    }

    ProtonBridgeStatus status;
    proton_bridge_get_status(m_engine, &status);

    QString state = QString::fromUtf8(reinterpret_cast<const char*>(status.state),
                                      strnlen(reinterpret_cast<const char*>(status.state), 16));

    qDebug() << "Sync status:" << state << "progress:" << status.progress
             << "contacts:" << status.synced_contacts << "/" << status.total_contacts;

    if (state == QLatin1String("complete")) {
        m_timer->stop();

        char *rt = proton_bridge_get_refresh_token(m_engine);
        char *uid = proton_bridge_get_uid(m_engine);
        if (rt && uid) {
            persistTokens(QString::fromUtf8(rt), QString::fromUtf8(uid));
        }
        if (rt) proton_bridge_free_string(rt);
        if (uid) proton_bridge_free_string(uid);

        // Persist derived mailbox passwords (encrypted via SignOn on next auth, plus QSettings cache)
        char *derived = proton_bridge_get_derived_passwords_json(m_engine);
        if (derived) {
            QString derivedJson = QString::fromUtf8(derived);
            proton_bridge_free_string(derived);
            if (!derivedJson.isEmpty() && derivedJson != QStringLiteral("null")) {
                QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
                settings.beginGroup(m_accountId);
                settings.setValue(QStringLiteral("derived_passwords"), derivedJson);
                settings.endGroup();
                proton_log(QStringLiteral("Persisted derived passwords for account ") + m_accountId);
                // Also update SignOn identity with derived passwords (encrypted storage)
                if (m_identity) {
                    SignOn::IdentityInfo info;
                    // Query current info async – for now store via QSettings cache is used as derived source
                    // Future: store via SignOn custom property "DerivedPasswords"
                }
            }
        }

        char *keysDbg = proton_bridge_get_keys_debug(m_engine);
        QString keysDebug = keysDbg ? QString::fromUtf8(keysDbg) : QString();
        if (keysDbg) proton_bridge_free_string(keysDbg);
        proton_log(QStringLiteral("Keys debug: ") + keysDebug);

        char *json = proton_bridge_get_synced_contacts_json(m_engine);
        if (json) {
            QByteArray jsonData(json);
            proton_bridge_free_string(json);

            bool ok = writeContactsToQtPIM(jsonData);
            if (ok) {
                emit success(getProfileName(), QStringLiteral("Sync completed"));
            } else {
                emit error(getProfileName(), QStringLiteral("Failed to write contacts"), Buteo::SyncResults::INTERNAL_ERROR);
                sendProtonNotification(QStringLiteral("Proton Contacts sync failed"), QStringLiteral("Failed to write contacts to phone"));
            }
        } else {
            emit success(getProfileName(), QStringLiteral("Sync completed (no contacts)"));
        }
    } else if (state == QLatin1String("error")) {
        m_timer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        proton_log(QStringLiteral("Sync error: ") + errMsg);
        char *keysDbg = proton_bridge_get_keys_debug(m_engine);
        QString keysDebug = keysDbg ? QString::fromUtf8(keysDbg) : QString();
        if (keysDbg) proton_bridge_free_string(keysDbg);
        proton_log(QStringLiteral("Keys debug on error: ") + keysDebug);
        // Emit authentication failure so Settings shows “Account not signed in” and user can re-enter credentials
        auto code = Buteo::SyncResults::AUTHENTICATION_FAILURE;
        sendProtonNotification(QStringLiteral("Proton Contacts sync failed"), errMsg);
        emit error(getProfileName(), errMsg, code);
    }
}

bool ProtonContactsPlugin::writeContactsToQtPIM(const QByteArray &json)
{
    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isArray()) {
        proton_log(QStringLiteral("Expected JSON array of contacts"));
        return false;
    }

    QtContacts::QContactCollection collection = findOrCreateCollection();
    if (collection.id().isNull()) {
        proton_log(QStringLiteral("ERROR: Failed to create/find Proton contacts collection"));
        return false;
    }
    proton_log(QStringLiteral("Using collection id=") + collection.id().toString());

    QtContacts::QContactCollectionFilter collectionFilter;
    collectionFilter.setCollectionId(collection.id());
    QList<QtContacts::QContact> oldContacts = m_manager->contacts(collectionFilter);
    if (!oldContacts.isEmpty()) {
        QList<QtContacts::QContactId> oldIds;
        for (const auto &c : oldContacts) {
            oldIds.append(c.id());
        }
        QMap<int, QtContacts::QContactManager::Error> errorMap;
        m_manager->removeContacts(oldIds, &errorMap);
        proton_log(QStringLiteral("Removed %1 old contacts from Proton collection").arg(oldIds.size()));
    }

    QJsonArray contacts = doc.array();
    QList<QtContacts::QContact> qtContacts;

    for (const QJsonValue &val : contacts) {
        QJsonObject obj = val.toObject();
        proton_log(QStringLiteral("Contact JSON: ") + QJsonDocument(obj).toJson(QJsonDocument::Compact).left(2000));

        QtContacts::QContact contact;
        contact.setCollectionId(collection.id());

        QtContacts::QContactSyncTarget st;
        st.setSyncTarget(QStringLiteral("proton"));
        contact.saveDetail(&st);

        QString firstName = obj.value(QLatin1String("first_name")).toString();
        QString lastName = obj.value(QLatin1String("last_name")).toString();
        QString displayName = obj.value(QLatin1String("display_name")).toString();

        if (firstName.isEmpty() && lastName.isEmpty() && !displayName.isEmpty()) {
            QStringList parts = displayName.split(QLatin1Char(' '));
            if (parts.size() >= 2) {
                firstName = parts.mid(0, parts.size() - 1).join(QLatin1Char(' '));
                lastName = parts.last();
            } else {
                firstName = displayName;
            }
        }

        if (!firstName.isEmpty() || !lastName.isEmpty()) {
            QtContacts::QContactName nameDetail;
            nameDetail.setFirstName(firstName);
            nameDetail.setLastName(lastName);
            contact.saveDetail(&nameDetail);
        }

        if (!displayName.isEmpty()) {
            QtContacts::QContactDisplayLabel labelDetail;
            labelDetail.setLabel(displayName);
            contact.saveDetail(&labelDetail);
        }

        QString contactUid = obj.value(QLatin1String("uid")).toString();
        if (!contactUid.isEmpty()) {
            QtContacts::QContactGuid guidDetail;
            guidDetail.setGuid(contactUid);
            contact.saveDetail(&guidDetail);
        }

        QJsonArray emails = obj.value(QLatin1String("emails")).toArray();
        for (const QJsonValue &ev : emails) {
            QJsonObject eo = ev.toObject();
            QString email = eo.value(QLatin1String("email")).toString();
            if (email.isEmpty()) continue;
            QtContacts::QContactEmailAddress emailDetail;
            emailDetail.setEmailAddress(email);
            QList<int> contexts;
            QJsonArray emailTypes = eo.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : emailTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!contexts.isEmpty()) emailDetail.setContexts(contexts);
            contact.saveDetail(&emailDetail);
        }

        QJsonArray phones = obj.value(QLatin1String("phones")).toArray();
        for (const QJsonValue &pv : phones) {
            QJsonObject po = pv.toObject();
            QString number = po.value(QLatin1String("number")).toString();
            if (number.isEmpty()) continue;
            QtContacts::QContactPhoneNumber phoneDetail;
            phoneDetail.setNumber(number);
            QList<int> subTypes;
            QList<int> contexts;
            QJsonArray phoneTypes = po.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : phoneTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("cell") || typeStr == QLatin1String("mobile"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeMobile;
                else if (typeStr == QLatin1String("fax"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeFax;
                else if (typeStr == QLatin1String("pager"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypePager;
                else if (typeStr == QLatin1String("voice"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeVoice;
                else if (typeStr == QLatin1String("video"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeVideo;
                else if (typeStr == QLatin1String("car"))
                    subTypes << QtContacts::QContactPhoneNumber::SubTypeCar;
                else if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!subTypes.isEmpty()) phoneDetail.setSubTypes(subTypes);
            if (!contexts.isEmpty()) phoneDetail.setContexts(contexts);
            contact.saveDetail(&phoneDetail);
        }

        QJsonArray addresses = obj.value(QLatin1String("addresses")).toArray();
        for (const QJsonValue &av : addresses) {
            QJsonObject ao = av.toObject();
            QtContacts::QContactAddress addrDetail;
            addrDetail.setStreet(ao.value(QLatin1String("street")).toString());
            addrDetail.setLocality(ao.value(QLatin1String("locality")).toString());
            addrDetail.setRegion(ao.value(QLatin1String("region")).toString());
            addrDetail.setPostcode(ao.value(QLatin1String("postal_code")).toString());
            addrDetail.setCountry(ao.value(QLatin1String("country")).toString());
            QList<int> contexts;
            QJsonArray addrTypes = ao.value(QLatin1String("types")).toArray();
            for (const QJsonValue &tv : addrTypes) {
                QString typeStr = tv.toString().toLower();
                if (typeStr == QLatin1String("home"))
                    contexts << QtContacts::QContactDetail::ContextHome;
                else if (typeStr == QLatin1String("work"))
                    contexts << QtContacts::QContactDetail::ContextWork;
            }
            if (!contexts.isEmpty()) addrDetail.setContexts(contexts);
            contact.saveDetail(&addrDetail);
        }

        QString org = obj.value(QLatin1String("organization")).toString();
        QString title = obj.value(QLatin1String("title")).toString();
        QString role = obj.value(QLatin1String("role")).toString();
        if (!org.isEmpty() || !title.isEmpty() || !role.isEmpty()) {
            QtContacts::QContactOrganization orgDetail;
            if (!org.isEmpty()) orgDetail.setName(org);
            if (!title.isEmpty()) orgDetail.setTitle(title);
            if (!role.isEmpty()) orgDetail.setRole(role);
            contact.saveDetail(&orgDetail);
        }

        QJsonArray notesArr = obj.value(QLatin1String("notes")).toArray();
        if (!notesArr.isEmpty()) {
            QStringList noteParts;
            for (const QJsonValue &nv : notesArr) {
                QString n = nv.toString();
                if (!n.isEmpty()) noteParts << n;
            }
            if (!noteParts.isEmpty()) {
                QtContacts::QContactNote noteDetail;
                noteDetail.setNote(noteParts.join(QLatin1String("\n")));
                contact.saveDetail(&noteDetail);
            }
        }

        QString birthday = obj.value(QLatin1String("birthday")).toString();
        if (!birthday.isEmpty()) {
            QtContacts::QContactBirthday bdayDetail;
            QDate bdayDate = QDate::fromString(birthday, Qt::ISODate);
            if (!bdayDate.isValid()) {
                bdayDate = QDate::fromString(birthday, QStringLiteral("yyyyMMdd"));
            }
            if (bdayDate.isValid()) {
                bdayDetail.setDate(bdayDate);
                contact.saveDetail(&bdayDetail);
            }
        }

        QString anniversary = obj.value(QLatin1String("anniversary")).toString();
        if (!anniversary.isEmpty()) {
            QtContacts::QContactAnniversary annDetail;
            QDate annDate = QDate::fromString(anniversary, Qt::ISODate);
            if (!annDate.isValid()) {
                annDate = QDate::fromString(anniversary, QStringLiteral("yyyyMMdd"));
            }
            if (annDate.isValid()) {
                annDetail.setOriginalDate(annDate);
                contact.saveDetail(&annDetail);
            }
        }

        QString nickname = obj.value(QLatin1String("nickname")).toString();
        if (!nickname.isEmpty()) {
            QtContacts::QContactNickname nickDetail;
            nickDetail.setNickname(nickname);
            contact.saveDetail(&nickDetail);
        }

        QString url = obj.value(QLatin1String("url")).toString();
        if (!url.isEmpty()) {
            QtContacts::QContactUrl urlDetail;
            urlDetail.setUrl(url);
            contact.saveDetail(&urlDetail);
        }

        QString gender = obj.value(QLatin1String("gender")).toString();
        if (!gender.isEmpty()) {
            QtContacts::QContactGender genderDetail;
            if (gender.compare(QLatin1String("Male"), Qt::CaseInsensitive) == 0) {
                genderDetail.setGender(QtContacts::QContactGender::GenderMale);
            } else if (gender.compare(QLatin1String("Female"), Qt::CaseInsensitive) == 0) {
                genderDetail.setGender(QtContacts::QContactGender::GenderFemale);
            } else {
                genderDetail.setGender(QtContacts::QContactGender::GenderMale);
            }
            contact.saveDetail(&genderDetail);
        }

        QJsonArray photosArr = obj.value(QLatin1String("photos")).toArray();
        if (!photosArr.isEmpty()) {
            QString photoUrl = photosArr.first().toString();
            if (!photoUrl.isEmpty()) {
                QtContacts::QContactAvatar avatarDetail;
                if (photoUrl.startsWith(QLatin1String("data:"))) {
                    avatarDetail.setImageUrl(QUrl(photoUrl));
                } else {
                    avatarDetail.setImageUrl(QUrl::fromEncoded(photoUrl.toUtf8()));
                }
                contact.saveDetail(&avatarDetail);
            }
        }

        qtContacts.append(contact);
    }

    if (!qtContacts.isEmpty()) {
        QMap<int, QtContacts::QContactManager::Error> errorMap;
        if (!m_manager->saveContacts(&qtContacts, &errorMap)) {
            proton_log(QStringLiteral("Failed to save contacts, error=") + QString::number(static_cast<int>(m_manager->error())));
            for (auto it = errorMap.constBegin(); it != errorMap.constEnd(); ++it) {
                proton_log(QStringLiteral("Save error index=%1 code=%2").arg(it.key()).arg(it.value()));
            }
            return false;
        }
        QCoreApplication::processEvents();
        proton_log(QStringLiteral("Saved %1 contacts via QContactManager, error=%2").arg(qtContacts.size()).arg(static_cast<int>(m_manager->error())));
    }

    return true;
}

QtContacts::QContactCollection ProtonContactsPlugin::findOrCreateCollection()
{
    QString collectionRemoteUid = QStringLiteral("proton-contacts-%1").arg(m_accountId);
    QString collectionName = QStringLiteral("Proton Contacts (%1)").arg(m_accountId);

    QList<QtContacts::QContactCollection> collections = m_manager->collections();
    for (const QtContacts::QContactCollection &col : collections) {
        QVariantMap extended = col.metaData(QtContacts::QContactCollection::KeyExtended).toMap();
        if (extended.value(QStringLiteral("remote_uid")).toString() == collectionRemoteUid) {
            proton_log(QStringLiteral("Found existing Proton collection for account ") + m_accountId);
            return col;
        }
    }

    QtContacts::QContactCollection collection;
    collection.setMetaData(QtContacts::QContactCollection::KeyName, collectionName);
    QVariantMap extended;
    extended.insert(QStringLiteral("remote_uid"), collectionRemoteUid);
    extended.insert(QStringLiteral("account_id"), m_accountId);
    collection.setMetaData(QtContacts::QContactCollection::KeyExtended, extended);

    if (!m_manager->saveCollection(&collection)) {
        proton_log(QStringLiteral("Failed to create Proton contacts collection, error=") + QString::number(static_cast<int>(m_manager->error())));
        return QtContacts::QContactCollection();
    }

    proton_log(QStringLiteral("Created Proton contacts collection for account ") + m_accountId);
    return collection;
}

void ProtonContactsPlugin::persistTokens(const QString &refreshToken, const QString &uid)
{
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("refresh_token"), refreshToken);
    settings.setValue(QStringLiteral("uid"), uid);
    settings.endGroup();
    proton_log(QStringLiteral("Persisted tokens for account ") + m_accountId);
}

QPair<QString, QString> ProtonContactsPlugin::loadPersistedTokens()
{
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString refreshToken = settings.value(QStringLiteral("refresh_token")).toString();
    QString uid = settings.value(QStringLiteral("uid")).toString();
    settings.endGroup();
    return qMakePair(refreshToken, uid);
}

Buteo::ClientPlugin *ProtonPluginLoader::createClientPlugin(const QString &aPluginName,
                                                            const Buteo::SyncProfile &aProfile,
                                                            Buteo::PluginCbInterface *aCbInterface)
{
    // The profile keys live on the top-level sync profile; dump everything
    // for diagnostics.
    QMap<QString, QString> keys = aProfile.allKeys();
    QStringList log;
    log << QStringLiteral("createClientPlugin: name=") + aProfile.name();
    for (auto it = keys.constBegin(); it != keys.constEnd(); ++it) {
        log << it.key() + QLatin1Char('=') + it.value();
    }
    proton_log(log.join(QStringLiteral(" | ")));
    return new ProtonContactsPlugin(aPluginName, aProfile, aCbInterface);
}
