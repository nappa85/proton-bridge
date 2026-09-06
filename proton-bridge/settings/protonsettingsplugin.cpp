// Proton account settings helper: explicit, user-confirmed purge of synced
// data (contacts collection + mKCal notebooks) for one account id.
// Mirrors the removal logic of the buteo sync plugin (proton_bridge_shim.cpp)
// but runs on demand from the Settings pulley menu instead of during sync.

#include "protonsettingsplugin.h"

#include <QContactManager>
#include <QContactCollection>
#include <QContactCollectionFilter>
#include <QDateTime>
#include <QDebug>
#include <QFile>
#include <QTimeZone>

#include <extendedcalendar.h>
#include <extendedstorage.h>
#include <notebook.h>
#include <KCalendarCore/Event>

static void purger_log(const QString &msg)
{
    QFile f("/tmp/proton-sync-debug.log");
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        f.write(QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8());
        f.write(" [settings-purge] ");
        f.write(msg.toUtf8());
        f.write("\n");
        f.close();
    }
    qDebug() << msg;
}

ProtonDataPurger::ProtonDataPurger(QObject *parent)
    : QObject(parent)
{
}

bool ProtonDataPurger::purgeData(int accountId)
{
    if (accountId <= 0) {
        purger_log(QStringLiteral("purgeData: invalid account id"));
        return false;
    }
    const QString id = QString::number(accountId);
    purger_log(QStringLiteral("purgeData: account ") + id);
    bool ok = true;

    // Contacts: remove our per-account collection (contacts go with it).
    {
        QtContacts::QContactManager manager(
            QStringLiteral("org.nemomobile.contacts.sqlite"));
        const QString remoteUid = QStringLiteral("proton-contacts-%1").arg(id);
        const QList<QtContacts::QContactCollection> collections = manager.collections();
        for (const QtContacts::QContactCollection &col : collections) {
            QVariantMap extended =
                col.metaData(QtContacts::QContactCollection::KeyExtended).toMap();
            if (extended.value(QStringLiteral("remote_uid")).toString() != remoteUid) {
                continue;
            }
            QtContacts::QContactCollectionFilter filter;
            filter.setCollectionId(col.id());
            const QList<QtContacts::QContact> contacts = manager.contacts(filter);
            if (!contacts.isEmpty()) {
                QList<QtContacts::QContactId> ids;
                ids.reserve(contacts.size());
                for (const QtContacts::QContact &c : contacts) {
                    ids.append(c.id());
                }
                QMap<int, QtContacts::QContactManager::Error> errorMap;
                manager.removeContacts(ids, &errorMap);
                purger_log(QStringLiteral("Removed %1 contacts from %2")
                               .arg(ids.size())
                               .arg(remoteUid));
            }
            if (!manager.removeCollection(col.id())) {
                purger_log(QStringLiteral("removeCollection failed ") + remoteUid);
                ok = false;
            } else {
                purger_log(QStringLiteral("Removed collection ") + remoteUid);
            }
        }
    }

    // Calendar: drop incidences, then erase our notebooks (current per-cal
    // ids plus the retired single per-account one).
    {
        mKCal::ExtendedCalendar::Ptr cal(
            new mKCal::ExtendedCalendar(QTimeZone::systemTimeZone()));
        mKCal::ExtendedStorage::Ptr storage =
            mKCal::ExtendedCalendar::defaultStorage(cal);
        if (!storage->open()) {
            purger_log(QStringLiteral("mKCal storage open failed"));
            return false;
        }
        const QString legacyUid = QStringLiteral("proton-calendar-%1").arg(id);
        const QString prefix = legacyUid + QLatin1Char('-');
        const mKCal::Notebook::List notebooks = storage->notebooks();
        for (const mKCal::Notebook::Ptr &nb : notebooks) {
            if (!nb) {
                continue;
            }
            if (nb->uid() != legacyUid && !nb->uid().startsWith(prefix)) {
                continue;
            }
            if (!storage->loadNotebookIncidences(nb->uid())) {
                purger_log(QStringLiteral("loadNotebookIncidences failed ") + nb->uid());
            }
            const KCalendarCore::Incidence::List existing = cal->incidences(nb->uid());
            for (const KCalendarCore::Incidence::Ptr &inc : existing) {
                KCalendarCore::Event::Ptr ev =
                    inc.dynamicCast<KCalendarCore::Event>();
                if (ev) {
                    cal->deleteEvent(ev);
                }
            }
            if (!storage->deleteNotebook(nb)) {
                purger_log(QStringLiteral("deleteNotebook failed ") + nb->uid());
                ok = false;
            } else {
                purger_log(QStringLiteral("Deleted notebook ") + nb->uid());
            }
        }
        if (!storage->save()) {
            purger_log(QStringLiteral("mKCal storage save failed"));
            ok = false;
        }
    }

    purger_log(QStringLiteral("purgeData done ok=") + (ok ? QStringLiteral("1") : QStringLiteral("0")));
    return ok;
}

void ProtonSettingsPlugin::registerTypes(const char *uri)
{
    qmlRegisterType<ProtonDataPurger>(uri, 1, 0, "ProtonDataPurger");
}
