#include "proton_bridge_shim.h"
#include <QDebug>
#include <QThread>
#include <QFile>
#include <QDateTime>
#include <QCoreApplication>

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

using namespace Proton;

static const QString PROTON_SERVICE_NAME = QStringLiteral("proton-carddav");

ProtonContactsPlugin::ProtonContactsPlugin(const QString &aPluginName,
                                           const Buteo::SyncProfile &aProfile,
                                           Buteo::PluginCbInterface *aCbInterface)
    : Buteo::ClientPlugin(aPluginName, aProfile, aCbInterface)
    , m_manager(new QtContacts::QContactManager(QStringLiteral("org.nemomobile.contacts.sqlite")))
{
    proton_log(QStringLiteral("ProtonContactsPlugin constructed: ") + aPluginName);
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
    proton_log(QStringLiteral("ProtonContactsPlugin::init()"));

    m_accountId = iProfile.key(QStringLiteral("accountid"));
    if (m_accountId.isEmpty()) {
        proton_log(QStringLiteral("ERROR: No accountid in sync profile"));
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

    proton_log(QStringLiteral("credentialsId=") + QString::number(authData.credentialsId())
             + " method=" + authData.method() + " mechanism=" + authData.mechanism());

    m_identity = SignOn::Identity::existingIdentity(authData.credentialsId(), this);
    if (!m_identity) {
        proton_log(QStringLiteral("ERROR: Unable to create SignOn identity for id=") + QString::number(authData.credentialsId()));
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

    SignOn::SessionData sessionData(authData.parameters());
    sessionData.setUiPolicy(SignOn::NoUserInteractionPolicy);
    m_authSession->process(sessionData, authData.mechanism());

    proton_log(QStringLiteral("SignOn auth session started"));
    return true;
}

void ProtonContactsPlugin::onSignOnResponse(const SignOn::SessionData &data)
{
    proton_log(QStringLiteral("onSignOnResponse()"));

    QString username = data.UserName();
    QString password = data.Secret();

    auto tokens = loadPersistedTokens();
    QString refreshToken = tokens.first;
    QString uid = tokens.second;

    proton_log(QStringLiteral("Got credentials: username=") + username
             + " refresh_token=" + (refreshToken.isEmpty() ? QStringLiteral("(none)") : QStringLiteral("(present)"))
             + " uid=" + (uid.isEmpty() ? QStringLiteral("(none)") : uid));

    m_engine = proton_bridge_create_engine(
        username.toUtf8().constData(),
        password.toUtf8().constData(),
        "",
        refreshToken.toUtf8().constData(),
        uid.toUtf8().constData()
    );

    if (!m_engine) {
        qWarning() << "Failed to create Proton sync engine";
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

        char *json = proton_bridge_get_synced_contacts_json(m_engine);
        if (json) {
            QByteArray jsonData(json);
            proton_bridge_free_string(json);

            bool ok = writeContactsToQtPIM(jsonData);
            if (ok) {
                emit success(getProfileName(), QStringLiteral("Sync completed"));
            } else {
                emit error(getProfileName(), QStringLiteral("Failed to write contacts"), Buteo::SyncResults::INTERNAL_ERROR);
            }
        } else {
            emit success(getProfileName(), QStringLiteral("Sync completed (no contacts)"));
        }
    } else if (state == QLatin1String("error")) {
        m_timer->stop();
        QString errMsg = QString::fromUtf8(reinterpret_cast<const char*>(status.error),
                                           strnlen(reinterpret_cast<const char*>(status.error), 256));
        proton_log(QStringLiteral("Sync error: ") + errMsg);
        emit error(getProfileName(), errMsg, Buteo::SyncResults::INTERNAL_ERROR);
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
    return new ProtonContactsPlugin(aPluginName, aProfile, aCbInterface);
}
