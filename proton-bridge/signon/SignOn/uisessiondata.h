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

#ifndef UISESSIONDATA_H
#define UISESSIONDATA_H

#include <SignOn/SessionData>

namespace SignOn {

enum QueryError {
    QUERY_ERROR_NONE = 0,
    QUERY_ERROR_GENERAL,
    QUERY_ERROR_NO_SIGNONUI,
    QUERY_ERROR_BAD_PARAMETERS,
    QUERY_ERROR_CANCELED,
    QUERY_ERROR_NOT_AVAILABLE,
    QUERY_ERROR_BAD_URL,
    QUERY_ERROR_BAD_CAPTCHA,
    QUERY_ERROR_BAD_CAPTCHA_URL,
    QUERY_ERROR_REFRESH_FAILED,
    QUERY_ERROR_FORBIDDEN,
    QUERY_ERROR_FORGOT_PASSWORD,
    QUERY_ERROR_NETWORK,
    QUERY_ERROR_SSL,
};

enum QueryMessageId {
    QUERY_MESSAGE_EMPTY = 0,
    QUERY_MESSAGE_LOGIN,
    QUERY_MESSAGE_NOT_AUTHORIZED
};

class UiSessionData : public SessionData
{
public:
    UiSessionData(const QVariantMap &data = QVariantMap()) { m_data = data; }

    SIGNON_SESSION_DECLARE_PROPERTY(int, QueryErrorCode)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, Caption)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, Title)
    SIGNON_SESSION_DECLARE_PROPERTY(int, QueryMessageId)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, QueryMessage)
    SIGNON_SESSION_DECLARE_PROPERTY(bool, QueryUserName)
    SIGNON_SESSION_DECLARE_PROPERTY(bool, QueryPassword)
    SIGNON_SESSION_DECLARE_PROPERTY(bool, RememberPassword)
    SIGNON_SESSION_DECLARE_PROPERTY(bool, ShowRealm)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, OpenUrl)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, FinalUrl)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, UrlResponse)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, CaptchaUrl)
    SIGNON_SESSION_DECLARE_PROPERTY(QByteArray, CaptchaImage)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, CaptchaResponse)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, ForgotPassword)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, ForgotPasswordUrl)
    SIGNON_SESSION_DECLARE_PROPERTY(bool, Confirm)
    SIGNON_SESSION_DECLARE_PROPERTY(QString, Icon)

};

} //namespace SignOn

Q_DECLARE_METATYPE(SignOn::UiSessionData)
#endif // UISESSIONDATA_H
