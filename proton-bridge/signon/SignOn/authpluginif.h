/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
/*!
 * @copyright Copyright (C) 2009-2011 Nokia Corporation.
 * @license LGPL
 */

#ifndef AUTHPLUGINIF_H
#define AUTHPLUGINIF_H

#include <QtCore/qobject.h>
#include <QtCore/qpointer.h>
#include <QtCore/qplugin.h>

#include <QVariantMap>
#include <SignOn/sessiondata.h>
#include <SignOn/uisessiondata.h>
#include <SignOn/signonerror.h>

QT_BEGIN_NAMESPACE
class QString;
class QStringList;
class QByteArray;
class QVariant;
QT_END_NAMESPACE

enum AuthPluginState {
    PLUGIN_STATE_NONE = 0,
    PLUGIN_STATE_RESOLVING,
    PLUGIN_STATE_CONNECTING,
    PLUGIN_STATE_SENDING,
    PLUGIN_STATE_WAITING,
    PLUGIN_STATE_PENDING,
    PLUGIN_STATE_REFRESHING,
    PLUGIN_STATE_CANCELING,
    PLUGIN_STATE_HOLDING,
    PLUGIN_STATE_DONE
};

#define SIGNON_PLUGIN_INSTANCE(pluginclass) \
        { \
            static AuthPluginInterface *_instance = 0; \
            if (!_instance)      \
                _instance = static_cast<AuthPluginInterface *>(new pluginclass()); \
            return _instance; \
        }

#define SIGNON_DECL_AUTH_PLUGIN(pluginclass) \
        Q_EXTERN_C AuthPluginInterface *auth_plugin_instance() \
        SIGNON_PLUGIN_INSTANCE(pluginclass)

class AuthPluginInterface : public QObject
{
    Q_OBJECT

public:
    AuthPluginInterface(QObject *parent = 0) : QObject(parent)
        { qRegisterMetaType<SignOn::Error>("SignOn::Error"); }

    virtual ~AuthPluginInterface() {}

    virtual QString type() const = 0;

    virtual QStringList mechanisms() const = 0;

    virtual void cancel() {}

    virtual void abort() {}

    virtual void process(const SignOn::SessionData &inData,
                         const QString &mechanism = QString()) = 0;

Q_SIGNALS:
    void result(const SignOn::SessionData &data);

    void store(const SignOn::SessionData &data);

    void error(const SignOn::Error &err);

    void userActionRequired(const SignOn::UiSessionData &data);

    void refreshed(const SignOn::UiSessionData &data);

    void statusChanged(const AuthPluginState state,
                       const QString &message = QString());

public Q_SLOTS:
    virtual void userActionFinished(const SignOn::UiSessionData &data) {
        Q_UNUSED(data);
    }

    virtual void refresh(const SignOn::UiSessionData &data) {
        emit refreshed(data);
    }

};

QT_BEGIN_NAMESPACE
 Q_DECLARE_INTERFACE(AuthPluginInterface,
                     "com.nokia.SingleSignOn.PluginInterface/1.3")
QT_END_NAMESPACE
#endif // AUTHPLUGINIF_H
