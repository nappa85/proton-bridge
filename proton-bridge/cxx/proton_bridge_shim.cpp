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

// ---- Calendar (single .so, single Sync Protocol "proton") ----
// Real implementation: SignOn (NoUserInteraction) → Rust CalendarSyncEngine
// (bootstrap → unlock → windowed decrypt → JSON) → QOrganizer mkcal.
// Mirrors ProtonContactsPlugin credential handling; per-account collection
// "Proton Calendar (<accountId>)", full-replacement sync via GUID
// "proton-cal-<accountId>-<eventId>" (recurrence limited to FREQ daily/weekly/
// monthly/yearly v1 – see FINDINGS_CALENDAR.md).
static const QString PROTON_CALDAV_SERVICE_NAME = QStringLiteral("proton-caldav");

ProtonCalendarPlugin::ProtonCalendarPlugin(const QString &aPluginName,
                                           const Buteo::SyncProfile &aProfile,
                                           Buteo::PluginCbInterface *aCbInterface)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
{
    proton_log(QStringLiteral("ProtonCalendarPlugin constructed: ") + aPluginName + " profile=" + getProfileName());
}
ProtonCalendarPlugin::~ProtonCalendarPlugin() {
    if (m_calEngine) {
        proton_calendar_destroy_engine(m_calEngine);
        m_calEngine = nullptr;
    }
}
bool ProtonCalendarPlugin::init() {
    proton_log(QStringLiteral("ProtonCalendarPlugin::init() profile=") + getProfileName());
    // Storage backend is mKCal + KCalendarCore (the documented Sailfish stack;
    // QtOrganizer is not shipped on this image). Probe open here so failures
    // surface at init instead of mid-sync.
    mKCal::ExtendedCalendar::Ptr cal(new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    mKCal::ExtendedStorage::Ptr storage = mKCal::ExtendedCalendar::defaultStorage(cal);
    if (!storage->open()) {
        proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal storage open failed"));
    } else {
        proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal ready, notebooks=") + QString::number(storage->notebooks().size()));
        mKCal::SqliteStorage::Ptr sql = storage.dynamicCast<mKCal::SqliteStorage>();
        if (sql) {
            proton_log(QStringLiteral("ProtonCalendarPlugin::init() mKCal db=") + sql->databaseName());
        }
    }
    m_accountId = iProfile.key(QStringLiteral("accountid"));
    if (m_accountId.isEmpty()) {
        QString profileName = getProfileName();
        QRegularExpression re("-(\\d+)$");
        QRegularExpressionMatch match = re.match(profileName);
        if (match.hasMatch()) {
            m_accountId = match.captured(1);
        }
    }
    if (m_accountId.isEmpty()) {
        m_accountId = iProfile.key(QStringLiteral("account_id"));
    }
    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: Cannot determine accountid for calendar"));
        return false;
    }
    m_accountManager = new Accounts::Manager(this);
    if (!m_accountManager) {
        return false;
    }
    m_inited = true;
    return requestCalendarCredentials();
}
bool ProtonCalendarPlugin::uninit() {
    if (m_calTimer) {
        m_calTimer->stop();
        delete m_calTimer;
        m_calTimer = nullptr;
    }
    if (m_calEngine) {
        proton_calendar_destroy_engine(m_calEngine);
        m_calEngine = nullptr;
    }
    m_credentialsReady = false;
    m_inited = false;
    return true;
}
bool ProtonCalendarPlugin::requestCalendarCredentials() {
    Accounts::AccountId accId = static_cast<Accounts::AccountId>(m_accountId.toUInt());
    Accounts::Account *account = Accounts::Account::fromId(m_accountManager, accId, this);
    if (!account) {
        proton_log(QStringLiteral("ERROR: Unable to load account ") + m_accountId);
        return false;
    }
    Accounts::Service service = m_accountManager->service(PROTON_CALDAV_SERVICE_NAME);
    if (!service.isValid()) {
        // Shared identity lives on the contacts service; fall back.
        service = m_accountManager->service(PROTON_SERVICE_NAME);
    }
    if (!service.isValid()) {
        proton_log(QStringLiteral("ERROR: Unable to find calendar/contacts service"));
        return false;
    }
    account->selectService(service);
    Accounts::AccountService *accountService = new Accounts::AccountService(account, service, this);
    Accounts::AuthData authData = accountService->authData();
    quint32 credentialsId = authData.credentialsId();
    if (credentialsId == 0) {
        account->selectService(service);
        QVariant raw = account->value(QStringLiteral("CredentialsId"));
        if (raw.isValid() && raw.toUInt() > 0) {
            credentialsId = raw.toUInt();
            account->setCredentialsId(credentialsId);
            account->sync();
        }
    }
    if (credentialsId == 0) {
        account->selectService(Accounts::Service());
        credentialsId = account->credentialsId();
        if (credentialsId > 0) {
            account->selectService(service);
        }
    }
    m_identity = SignOn::Identity::existingIdentity(credentialsId, this);
    if (!m_identity) {
        return false;
    }
    m_authSession = m_identity->createSession(authData.method());
    if (!m_authSession) {
        return false;
    }
    connect(m_authSession, &SignOn::AuthSession::response,
            this, &ProtonCalendarPlugin::onCalendarSignOnResponse);
    connect(m_authSession, &SignOn::AuthSession::error,
            this, &ProtonCalendarPlugin::onCalendarSignOnError);
    SignOn::SessionData sessionData;
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());
    return true;
}
void ProtonCalendarPlugin::onCalendarSignOnResponse(const SignOn::SessionData &data) {
    bool twoFARequired = data.getProperty(QStringLiteral("TwoFARequired")).toBool();
    if (twoFARequired) {
        emit error(getProfileName(), QStringLiteral("Two-factor authentication required – please update credentials in Settings → Proton and enter OTP code"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }
    QString username = data.UserName();
    QString userNameViaProperty = data.getProperty(QStringLiteral("UserName")).toString();
    if (username.isEmpty() && !userNameViaProperty.isEmpty()) username = userNameViaProperty;
    QString accessToken = data.getProperty(QStringLiteral("AccessToken")).toString();
    QString refreshToken = data.getProperty(QStringLiteral("RefreshToken")).toString();
    QString uid = data.getProperty(QStringLiteral("Uid")).toString();
    QString derivedJson = data.getProperty(QStringLiteral("DerivedPasswords")).toString();
    if (refreshToken.isEmpty() || uid.isEmpty()) {
        auto tokens = loadPersistedCalendarTokens();
        if (refreshToken.isEmpty()) refreshToken = tokens.first;
        if (uid.isEmpty()) uid = tokens.second;
    }
    if (derivedJson.isEmpty()) {
        QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
        settings.beginGroup(m_accountId);
        derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
        settings.endGroup();
        if (derivedJson.isEmpty() && !uid.isEmpty()) {
            settings.beginGroup(uid);
            derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
            settings.endGroup();
        }
        if (derivedJson.isEmpty() && !username.isEmpty()) {
            settings.beginGroup(username);
            derivedJson = settings.value(QStringLiteral("derived_passwords")).toString();
            settings.endGroup();
        }
    }
    if (accessToken.isEmpty() && refreshToken.isEmpty()) {
        emit error(getProfileName(), QStringLiteral("No auth tokens received"), Buteo::SyncResults::AUTHENTICATION_FAILURE);
        return;
    }
    m_calEngine = proton_calendar_create_engine_with_derived(
        username.toUtf8().constData(),
        accessToken.toUtf8().constData(),
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData(),
        derivedJson.toUtf8().constData());
    if (!m_calEngine) {
        emit error(getProfileName(), QStringLiteral("Failed to create calendar engine"), Buteo::SyncResults::INTERNAL_ERROR);
        return;
    }
    m_credentialsReady = true;
    m_calTimer = new QTimer(this);
    connect(m_calTimer, &QTimer::timeout, this, &ProtonCalendarPlugin::pollCalendarStatus);
    if (!startSync()) {
        emit error(getProfileName(), QStringLiteral("Failed to start calendar sync"), Buteo::SyncResults::INTERNAL_ERROR);
    }
}
void ProtonCalendarPlugin::onCalendarSignOnError(const SignOn::Error &signOnError) {
    emit error(getProfileName(), QStringLiteral("Authentication failed: ") + signOnError.message(), Buteo::SyncResults::AUTHENTICATION_FAILURE);
}
bool ProtonCalendarPlugin::startSync() {
    if (!m_credentialsReady) {
        return true;
    }
    if (!m_calEngine) {
        emit error(getProfileName(), QStringLiteral("Calendar engine not initialized"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }
    if (!proton_calendar_start_sync(m_calEngine)) {
        emit error(getProfileName(), QStringLiteral("Failed to start calendar sync"), Buteo::SyncResults::INTERNAL_ERROR);
        return false;
    }
    m_calTimer->start(500);
    return true;
}
void ProtonCalendarPlugin::pollCalendarStatus() {
    if (!m_calEngine) return;
    ProtonBridgeStatus status;
    proton_calendar_get_status(m_calEngine, &status);
    QString state = QString::fromUtf8(reinterpret_cast<const char*>(status.state),
                                      strnlen(reinterpret_cast<const char*>(status.state), 16));
    if (state == QLatin1String("complete")) {
        m_calTimer->stop();
        char *rt = proton_calendar_get_refresh_token(m_calEngine);
        char *uid = proton_calendar_get_uid(m_calEngine);
        if (rt && uid) {
            persistCalendarTokens(QString::fromUtf8(rt), QString::fromUtf8(uid));
        }
        if (rt) proton_bridge_free_string(rt);
        if (uid) proton_bridge_free_string(uid);
        char *keysDbg = proton_calendar_get_keys_debug(m_calEngine);
        if (keysDbg) {
            proton_log(QStringLiteral("Calendar keys debug: ") + QString::fromUtf8(keysDbg));
            proton_bridge_free_string(keysDbg);
        }
        char *json = proton_calendar_get_events_json(m_calEngine);
        if (json) {
            QByteArray jsonData(json);
            proton_bridge_free_string(json);
            if (writeEventsToMkCal(jsonData)) {
                emit success(getProfileName(), QStringLiteral("Calendar sync completed"));
            } else {
                emit error(getProfileName(), QStringLiteral("Failed to write calendar events"), Buteo::SyncResults::INTERNAL_ERROR);
                sendProtonNotification(QStringLiteral("Proton Calendar sync failed"), QStringLiteral("Failed to write events to phone"));
            }
        } else {
            emit success(getProfileName(), QStringLiteral("Calendar sync completed (no events)"));
        }
    } else if (state == QLatin1String("error")) {
        m_calTimer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        proton_log(QStringLiteral("Calendar sync error: ") + errMsg);
        sendProtonNotification(QStringLiteral("Proton Calendar sync failed"), errMsg);
        emit error(getProfileName(), errMsg, Buteo::SyncResults::AUTHENTICATION_FAILURE);
    }
}
// Forward: version-independent unix→UTC (defined with the other file-local
// helpers below; needed by parseCalTime).
static QDateTime utcFromUnix(qint64 secs);
QDateTime ProtonCalendarPlugin::parseCalTime(const QString &ical, qint64 unixFallback, const QString &tz) {
    // Accept UTC (…Z), floating, DATE-only, and TZID-stripped values (parse_ical
    // already strips params). Fall back to row unix time + timezone.
    auto parseFormats = [&](const QString &v) -> QDateTime {
        QString s = v.trimmed();
        if (s.isEmpty()) return QDateTime();
        // DATE-only all-day.
        if (s.length() == 8 && !s.contains('T')) {
            QDate d = QDate::fromString(s, QStringLiteral("yyyyMMdd"));
            if (d.isValid()) return QDateTime(d, QTime(0, 0), Qt::UTC);
        }
        QStringList fmts = { QStringLiteral("yyyyMMdd'T'HHmmss'Z'"), QStringLiteral("yyyyMMdd'T'HHmmss"), QStringLiteral("yyyy-MM-ddTHH:mm:ss'Z'"), QStringLiteral("yyyy-MM-ddTHH:mm:ss") };
        for (const QString &f : fmts) {
            QDateTime dt = QDateTime::fromString(s, f);
            if (dt.isValid()) {
                if (s.endsWith('Z')) dt.setTimeSpec(Qt::UTC);
                return dt;
            }
        }
        return QDateTime();
    };
    QDateTime dt = parseFormats(ical);
    if (dt.isValid()) {
        // Floating wall-clock + known event timezone (e.g. TZID-stripped
        // "20260914T200000" + StartTimezone Europe/Rome): attach the zone so
        // occurrence instants match the server's recurrenceId instants
        // (T15 exception linkage, verified live 2026-09-06).
        if (!ical.trimmed().endsWith('Z') && dt.timeSpec() == Qt::LocalTime
            && !tz.isEmpty() && tz != QStringLiteral("UTC")) {
            QTimeZone zone(tz.toUtf8());
            if (zone.isValid()) {
                QDateTime zoned(dt.date(), dt.time(), zone);
                if (zoned.isValid()) return zoned;
            }
        }
        return dt;
    }
    if (unixFallback > 0) {
        // Qt 5.6 (Sailfish): no fromSecsSinceEpoch (Qt 5.8+); use the
        // version-independent UTC construction (see utcFromUnix).
        return utcFromUnix(unixFallback);
    }
    return QDateTime();
}
QString ProtonCalendarPlugin::findOrCreateNotebook(mKCal::ExtendedCalendar::Ptr cal,
                                                       mKCal::ExtendedStorage::Ptr storage,
                                                       const QString &calId,
                                                       const QString &calName) {
    Q_UNUSED(cal);
    // One notebook per Proton calendar (T20 "porcodio" must be visibly
    // separate). Legacy single notebook from the first version is cleaned
    // up by the caller.
    QString nbUid = QStringLiteral("proton-calendar-%1-%2").arg(m_accountId, calId);
    mKCal::Notebook::List nbs = storage->notebooks();
    for (const mKCal::Notebook::Ptr &nb : nbs) {
        if (nb && nb->uid() == nbUid) {
            return nbUid;
        }
    }
    mKCal::Notebook::Ptr nb(new mKCal::Notebook());
    nb->setUid(nbUid);
    nb->setName(calName.isEmpty() ? QStringLiteral("Proton Calendar (%1)").arg(m_accountId) : calName);
    nb->setDescription(QStringLiteral("Proton Calendar"));
    nb->setPluginName(QStringLiteral("proton"));
    nb->setAccount(m_accountId);
    nb->setSyncProfile(getProfileName());
    nb->setIsVisible(true);
    nb->setIsReadOnly(false);
    nb->setEventsAllowed(true);
    nb->setTodosAllowed(false);
    nb->setJournalsAllowed(false);
    if (!storage->addNotebook(nb)) {
        proton_log(QStringLiteral("Failed to create calendar notebook ") + nbUid);
        return QString();
    }
    proton_log(QStringLiteral("Created calendar notebook ") + nbUid);
    return nbUid;
}

static QString stripMailto(const QString &s) {
    QString email = s.trimmed();
    int mailto = email.toLower().indexOf(QStringLiteral("mailto:"));
    if (mailto >= 0) {
        email = email.mid(mailto + 7).split(';').first().trimmed();
    }
    return email;
}

// Unambiguous unix→UTC conversion. QDateTime::fromTime_t + setTimeSpec
// round-trips through local time on some Qt versions (observed +2h shift on
// device Qt 5.6: rid 20:00Z became 22:00Z, breaking recursAt linkage, while
// host Qt kept the instant). Epoch + addSecs is identical everywhere.
static QDateTime utcFromUnix(qint64 secs) {
    QDateTime dt(QDate(1970, 1, 1), QTime(0, 0, 0), Qt::UTC);
    return dt.addSecs(secs);
}

// Fill a KCalendarCore event from one JSON row (times precomputed by caller).
// Recurrence linkage (recurrenceId) is handled by the caller: pass 1 adds
// masters, pass 2 dissociates exceptions from them (T15).
static void fillEventFromJson(const KCalendarCore::Event::Ptr &ev, const QJsonObject &o,
                              const QString &uid, const QDateTime &start, const QDateTime &end,
                              bool fullDay) {
    ev->setUid(uid);
    QString summary = o.value(QLatin1String("summary")).toString();
    ev->setSummary(summary.isEmpty() ? uid : summary);
    ev->setDescription(o.value(QLatin1String("description")).toString());
    ev->setLocation(o.value(QLatin1String("location")).toString());
    ev->setAllDay(fullDay);
    ev->setDtStart(start);
    ev->setDtEnd(end);
    // Recurrence: FREQ + COUNT/UNTIL from the raw RRULE (verified T09–T14).
    QString rrule = o.value(QLatin1String("rrule")).toString().toUpper();
    if (rrule.contains(QStringLiteral("FREQ="))) {
        KCalendarCore::RecurrenceRule::PeriodType period =
            KCalendarCore::RecurrenceRule::rNone;
        if (rrule.contains(QStringLiteral("FREQ=DAILY"))) period = KCalendarCore::RecurrenceRule::rDaily;
        else if (rrule.contains(QStringLiteral("FREQ=WEEKLY"))) period = KCalendarCore::RecurrenceRule::rWeekly;
        else if (rrule.contains(QStringLiteral("FREQ=MONTHLY"))) period = KCalendarCore::RecurrenceRule::rMonthly;
        else if (rrule.contains(QStringLiteral("FREQ=YEARLY"))) period = KCalendarCore::RecurrenceRule::rYearly;
        if (period != KCalendarCore::RecurrenceRule::rNone) {
            KCalendarCore::RecurrenceRule *rule = new KCalendarCore::RecurrenceRule();
            rule->setRecurrenceType(period);
            rule->setFrequency(1);
            rule->setStartDt(start);
            for (const QString &part : rrule.split(';')) {
                if (part.startsWith(QStringLiteral("COUNT="))) {
                    bool ok = false;
                    int count = part.mid(6).toInt(&ok);
                    if (ok && count > 0) rule->setDuration(count);
                } else if (part.startsWith(QStringLiteral("UNTIL="))) {
                    QDateTime until = ProtonCalendarPlugin::parseCalTime(part.mid(6), 0, QStringLiteral("UTC"));
                    if (until.isValid()) rule->setEndDt(until);
                }
            }
            ev->recurrence()->addRRule(rule); // recurrence takes ownership
        }
    }
    // EXDATEs (T14 single-occurrence deletes).
    QJsonArray exdates = o.value(QLatin1String("exdates")).toArray();
    for (const QJsonValue &xv : exdates) {
        QDateTime ex = ProtonCalendarPlugin::parseCalTime(xv.toString(), 0, QStringLiteral("UTC"));
        if (ex.isValid()) ev->recurrence()->addExDateTime(ex);
    }
    // Attendees (mailto: identities from merged fragments, T16).
    QJsonArray atts = o.value(QLatin1String("attendees")).toArray();
    for (const QJsonValue &av : atts) {
        QString email = stripMailto(av.toString());
        if (email.isEmpty()) continue;
        ev->addAttendee(KCalendarCore::Attendee(QString(), email));
    }
    QString organizer = stripMailto(o.value(QLatin1String("organizer")).toString());
    if (!organizer.isEmpty()) ev->setOrganizer(organizer);
    QString status = o.value(QLatin1String("status")).toString().toUpper();
    if (status == QLatin1String("CONFIRMED")) ev->setStatus(KCalendarCore::Incidence::StatusConfirmed);
    else if (status == QLatin1String("CANCELLED")) ev->setStatus(KCalendarCore::Incidence::StatusCanceled);
    else if (status == QLatin1String("TENTATIVE")) ev->setStatus(KCalendarCore::Incidence::StatusTentative);
    if (o.value(QLatin1String("transp")).toString().compare(QLatin1String("TRANSPARENT"), Qt::CaseInsensitive) == 0) {
        ev->setTransparency(KCalendarCore::Event::Transparent);
    }
    QString color = o.value(QLatin1String("color")).toString();
    if (!color.isEmpty()) ev->setColor(color);
}

// Shared start/end computation (unix fallback, full-day exclusive-end fix).
static bool eventTimes(const QJsonObject &o, QDateTime &start, QDateTime &end, bool &fullDay) {
    fullDay = o.value(QLatin1String("full_day")).toBool(false);
    start = ProtonCalendarPlugin::parseCalTime(o.value(QLatin1String("dtstart")).toString(),
                                               o.value(QLatin1String("start_time")).toVariant().toLongLong(),
                                               o.value(QLatin1String("start_timezone")).toString());
    end = ProtonCalendarPlugin::parseCalTime(o.value(QLatin1String("dtend")).toString(),
                                             o.value(QLatin1String("end_time")).toVariant().toLongLong(),
                                             o.value(QLatin1String("end_timezone")).toString());
    if (!start.isValid()) start = QDateTime::currentDateTimeUtc();
    if (!end.isValid() || end < start) end = start.addSecs(fullDay ? 86400 : 3600);
    if (fullDay) {
        // Proton/mKCal all-day DTEND is exclusive but the Calendar app reads it
        // inclusive: T03 (1 day) showed 2, T04 (3 days) showed 4 (live 2026-09-06).
        end = end.addDays(-1);
        if (end < start) end = start;
    }
    return true;
}

bool ProtonCalendarPlugin::writeEventsToMkCal(const QByteArray &json) {
    QJsonDocument doc = QJsonDocument::fromJson(json);
    if (!doc.isArray()) {
        proton_log(QStringLiteral("Expected JSON array of events"));
        return false;
    }
    mKCal::ExtendedCalendar::Ptr cal(
        new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
    mKCal::ExtendedStorage::Ptr storage = mKCal::ExtendedCalendar::defaultStorage(cal);
    if (!storage->open()) {
        proton_log(QStringLiteral("mKCal storage open failed"));
        return false;
    }
    QJsonArray arr = doc.array();
    // Group rows by Proton calendar (one notebook each, T20 separation).
    QMap<QString, QString> calNames;
    QMap<QString, QList<int>> byCal;
    for (int i = 0; i < arr.size(); ++i) {
        QJsonObject o = arr.at(i).toObject();
        QString cid = o.value(QLatin1String("calendar_id")).toString();
        if (cid.isEmpty()) cid = QStringLiteral("default");
        if (!calNames.contains(cid)) {
            calNames[cid] = o.value(QLatin1String("calendar_name")).toString();
        }
        byCal[cid].append(i);
    }
    // Migration + full replacement: drop events from ALL our notebooks,
    // including the legacy single per-account notebook of the first version.
    QString legacyUid = QStringLiteral("proton-calendar-%1").arg(m_accountId);
    QString prefix = QStringLiteral("proton-calendar-%1-").arg(m_accountId);
    mKCal::Notebook::List nbs = storage->notebooks();
    for (const mKCal::Notebook::Ptr &nb : nbs) {
        if (!nb) continue;
        if (nb->uid() != legacyUid && !nb->uid().startsWith(prefix)) continue;
        if (nb->uid() == legacyUid) {
            // Retire the v1 notebook entirely (events move to per-cal notebooks).
            if (storage->deleteNotebook(nb)) {
                proton_log(QStringLiteral("Retired legacy notebook ") + legacyUid);
            }
            continue;
        }
        if (!storage->loadNotebookIncidences(nb->uid())) continue;
        KCalendarCore::Incidence::List existing = cal->incidences(nb->uid());
        int removed = 0;
        for (const KCalendarCore::Incidence::Ptr &inc : existing) {
            KCalendarCore::Event::Ptr ev = inc.dynamicCast<KCalendarCore::Event>();
            if (ev && cal->deleteEvent(ev)) removed++;
        }
        if (removed > 0) {
            proton_log(QStringLiteral("Removed %1 old events from %2").arg(removed).arg(nb->uid()));
        }
    }
    int saved = 0;
    auto rowRecurrenceId = [](const QJsonObject &o) {
        return o.value(QLatin1String("recurrence_id")).toVariant().toLongLong();
    };
    for (auto it = byCal.constBegin(); it != byCal.constEnd(); ++it) {
        QString nbUid = findOrCreateNotebook(cal, storage, it.key(), calNames.value(it.key()));
        if (nbUid.isEmpty()) continue;
        if (!storage->loadNotebookIncidences(nbUid)) {
            proton_log(QStringLiteral("loadNotebookIncidences failed, continuing anyway"));
        }
        // Pass 1: masters (no recurrence-id). Pass 2 decomposes exceptions
        // into master-EXDATE + standalone edited event (T15).
        for (int pass = 0; pass < 2; ++pass) {
        for (int idx : it.value()) {
            QJsonObject o = arr.at(idx).toObject();
        QString uid = o.value(QLatin1String("uid")).toString();
        QString summary = o.value(QLatin1String("summary")).toString();
        if (uid.isEmpty() && summary.isEmpty()) continue;
        qint64 recurrenceId = rowRecurrenceId(o);
        bool isException = recurrenceId > 0;
        if ((pass == 0) == isException) continue;
        QDateTime start, end;
        bool fullDay = false;
        eventTimes(o, start, end, fullDay);
        if (!isException) {
            KCalendarCore::Event::Ptr ev(new KCalendarCore::Event());
            fillEventFromJson(ev, o, uid, start, end, fullDay);
            if (cal->addEvent(ev, nbUid)) {
                saved++;
            } else {
                proton_log(QStringLiteral("addEvent failed uid=") + uid.left(64));
            }
            continue;
        }
        // Exception occurrence (T15): mkcal's exception machinery
        // (dissociate + same-UID save) never persisted the row — the
        // dissociated object isn't inserted by dissociate, and explicitly
        // added copies with recurrenceId are silently skipped at save.
        // Decompose instead, using only proven primitives: EXDATE the
        // original occurrence on the master + save the edited occurrence
        // as a plain event with a stable suffixed UID. Display result is
        // identical; no recurrenceId anywhere.
        QDateTime rid = utcFromUnix(recurrenceId);
        KCalendarCore::Event::Ptr master = cal->event(uid);
        if (master && master->recursAt(rid)) {
            master->recurrence()->addExDateTime(rid);
        } else if (master) {
            proton_log(QStringLiteral("exception rid matches no occurrence, standalone only uid=") + uid.left(64));
        } else {
            proton_log(QStringLiteral("exception without master, standalone uid=") + uid.left(64));
        }
        KCalendarCore::Event::Ptr solo(new KCalendarCore::Event());
        QString soloUid = QStringLiteral("%1#%2").arg(uid, QString::number(recurrenceId));
        fillEventFromJson(solo, o, soloUid, start, end, fullDay);
        if (cal->addEvent(solo, nbUid)) {
            saved++;
        } else {
            proton_log(QStringLiteral("addEvent exception failed uid=") + uid.left(64));
        }
        continue;
        } // per-event rows of this Proton calendar
        } // pass 1 masters / pass 2 exceptions
    } // per Proton calendar notebook
    if (!storage->save()) {
        proton_log(QStringLiteral("mKCal storage save failed"));
        return false;
    }
    proton_log(QStringLiteral("Saved %1 calendar events to mkcal").arg(saved));
    return true;
}
void ProtonCalendarPlugin::persistCalendarTokens(const QString &refreshToken, const QString &uid) {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    settings.setValue(QStringLiteral("refresh_token"), refreshToken);
    settings.setValue(QStringLiteral("uid"), uid);
    settings.endGroup();
}
QPair<QString, QString> ProtonCalendarPlugin::loadPersistedCalendarTokens() {
    QSettings settings(QStringLiteral("proton"), QStringLiteral("sync-tokens"));
    settings.beginGroup(m_accountId);
    QString rt = settings.value(QStringLiteral("refresh_token")).toString();
    QString uid = settings.value(QStringLiteral("uid")).toString();
    settings.endGroup();
    return qMakePair(rt, uid);
}
void ProtonCalendarPlugin::abortSync(Sync::SyncStatus aStatus) {
    Q_UNUSED(aStatus);
    if (m_calTimer) m_calTimer->stop();
}
bool ProtonCalendarPlugin::cleanUp() { return true; }
Buteo::SyncResults ProtonCalendarPlugin::getSyncResults() const { return Buteo::SyncResults(); }
void ProtonCalendarPlugin::connectivityStateChanged(Sync::ConnectivityType aType, bool aState) { Q_UNUSED(aType); Q_UNUSED(aState); }

Buteo::ClientPlugin *ProtonPluginLoader::createClientPlugin(const QString &aPluginName,
                                                            const Buteo::SyncProfile &aProfile,
                                                            Buteo::PluginCbInterface *aCbInterface)
{
    // Single libproton-client.so serves both contacts and calendar (same Sync Protocol "proton")
    // Distinguish by sync profile name (proton-carddav-* vs proton-caldav-*)
    QMap<QString, QString> keys = aProfile.allKeys();
    QStringList log;
    log << QStringLiteral("createClientPlugin: name=") + aProfile.name();
    for (auto it = keys.constBegin(); it != keys.constEnd(); ++it) {
        log << it.key() + QLatin1Char('=') + it.value();
    }
    proton_log(log.join(QStringLiteral(" | ")));
    if (aProfile.name().contains(QStringLiteral("caldav")) || aProfile.name().contains(QStringLiteral("calendar")) || aProfile.name().contains(QStringLiteral("Calendar"))) {
        return new ProtonCalendarPlugin(aPluginName, aProfile, aCbInterface);
    }
    return new ProtonContactsPlugin(aPluginName, aProfile, aCbInterface);
}
