import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0

/*
 * Proton account creation.
 *
 * A custom agent is used (instead of OnlineSyncAccountCreationAgent) because:
 *  - the account must not be created until the credentials are verified
 *    (including the two-factor code when TOTP is enabled);
 *  - the OTP code is collected in this page rather than through signon-ui:
 *    the in-process entry dialog of this jolla-signon-ui build crashes
 *    (SIGSEGV), so the "proton" SignOn plugin instead returns a
 *    TwoFARequired result carrying the locked-session tokens, and this UI
 *    completes the credentials with the code the user typed.
 *
 * Flow (all on one page, which is never popped mid-flow):
 *   1. User enters username/password, presses Sign in.
 *   2. AccountManager.createAccount("proton") creates a disabled account and
 *      Account.createSignInCredentials("Jolla","Jolla") runs the "proton"
 *      SignOn plugin (SRP login).
 *   3. If the result contains TwoFARequired, an OTP field is revealed; the
 *      user types the 6-digit code and the credentials are completed via
 *      Account.updateSignInCredentials with TwoFactorPassword + the locked
 *      tokens (POST /auth/v4/2fa upgrades the locked session in place).
 *   4. Only tokens (AccessToken/RefreshToken/Uid) are persisted via the
 *      plugin's store(); the password stays in the signond identity.
 *   5. On success the account is enabled and saved; buteo's AccountsHelper
 *      creates the sync profile when the account syncs.
 */
AccountCreationAgent {
    id: root

    function _writeDebug(message) {
        console.log("proton: " + message)
    }

    function _fail(message) {
        console.log("Proton account creation failed:", message)
        pageRoot._busy = false
        pageRoot._errorMessage = message
        delayDeletion = false
        if (creationAccount.identifier > 0 && !pageRoot._needsTwoFA) {
            var id = creationAccount.identifier
            creationAccount.identifier = 0
            var acc = accountManager.account(id)
            if (acc) acc.remove()
        }
    }

    function _setCredentialsId(identityId) {
        // QML numbers are double; convertValue rejects double for CredentialsId.
        // Pass as string – Accounts DB will store as type 's' but toUInt() still parses it.
        var intId = parseInt(identityId)
        if (isNaN(intId) || intId === 0) {
            console.log("proton: invalid identityId", identityId)
            return false
        }
        var strId = "" + intId
        console.log("proton: _setCredentialsId setting CredentialsId to string \"" + strId + "\"")
        creationAccount.setConfigurationValue("", "CredentialsId", strId)
        creationAccount.setConfigurationValue("proton-carddav", "CredentialsId", strId)
        return true
    }

    initialPage: Page {
        id: pageRoot

        property bool _busy
        property string _errorMessage
        property bool _needsTwoFA
        property string _pendingAccessToken
        property string _pendingRefreshToken
        property string _pendingUid
        property string _pendingUsername
        property string _pendingPassword

        backNavigation: !_busy

        on_BusyChanged: {
            if (_busy) root.delayDeletion = true
            else if (!_needsTwoFA && !creationAccount._flowComplete) root.delayDeletion = false
        }
        on_NeedsTwoFAChanged: {
            if (_needsTwoFA) root.delayDeletion = true
        }

        SilicaFlickable {
            anchors.fill: parent
            contentHeight: header.height + column.height + Theme.paddingLarge

            PageHeader {
                id: header
                //% "Add Proton account"
                title: qsTr("Add Proton account")
            }

            Column {
                id: column
                anchors { top: header.bottom; left: parent.left; right: parent.right }
                spacing: Theme.paddingLarge

                Item {
                    width: parent.width
                    height: Theme.iconSizeLarge

                    Image {
                        id: providerIcon
                        anchors {
                            top: parent.top
                            left: parent.left
                            leftMargin: Theme.horizontalPageMargin
                        }
                        width: Theme.iconSizeLarge
                        height: width
                        source: root.accountProvider.iconName
                    }
                    Label {
                        anchors {
                            left: providerIcon.right
                            leftMargin: Theme.paddingLarge
                            right: parent.right
                            rightMargin: Theme.horizontalPageMargin
                            verticalCenter: parent.verticalCenter
                        }
                        text: root.accountProvider.displayName
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeLarge
                    }
                }

                AccountUsernameField {
                    id: usernameField
                    enabled: !pageRoot._busy
                    visible: !pageRoot._needsTwoFA
                }

                PasswordField {
                    id: passwordField
                    enabled: !pageRoot._busy
                    visible: !pageRoot._needsTwoFA
                }

                Column {
                    width: parent.width
                    spacing: Theme.paddingLarge
                    visible: pageRoot._needsTwoFA

                    Label {
                        //% "Two-factor authentication is enabled on this account. Enter the 6-digit verification code from your authenticator app."
                        text: qsTr("Two-factor authentication is enabled on this account. Enter the 6-digit verification code from your authenticator app.")
                        wrapMode: Text.Wrap
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeSmall
                    }

                    TextField {
                        id: otpField
                        width: parent.width
                        //% "Verification code"
                        label: qsTr("Verification code")
                        //% "Enter verification code"
                        placeholderText: qsTr("Enter verification code")
                        inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                        enabled: !pageRoot._busy
                        EnterKey.enabled: text.length >= 6
                        EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                        errorHighlight: text.length > 0 && text.length != 6
                        EnterKey.onClicked: verifyButton.clicked()
                    }

                    Button {
                        id: verifyButton
                        anchors.horizontalCenter: parent.horizontalCenter
                        //% "Verify"
                        text: qsTr("Verify")
                        enabled: !pageRoot._busy && otpField.text.length == 6
                        onClicked: {
                            pageRoot._errorMessage = ""
                            pageRoot._busy = true
                            root.delayDeletion = true
                            console.log("proton: verify OTP for " + pageRoot._pendingUsername + " pw_len=" + pageRoot._pendingPassword.length + " code=" + otpField.text)
                            console.log("proton: pending AccessToken=" + (pageRoot._pendingAccessToken ? "yes" : "no") + " RefreshToken=" + (pageRoot._pendingRefreshToken ? "yes" : "no"))
                            var sip = creationAccount.signInParameters("proton-carddav",
                                                                      pageRoot._pendingUsername,
                                                                      "x")
                            sip.setParameter("Password", pageRoot._pendingPassword)
                            console.log("proton: verify sip username=" + sip.username + " password_len=" + (sip.password ? sip.password.length : 0) + " hasPasswordParam set")
                            sip.setParameter("TwoFactorPassword", otpField.text)
                            sip.setParameter("AccessToken", pageRoot._pendingAccessToken)
                            sip.setParameter("RefreshToken", pageRoot._pendingRefreshToken)
                            sip.setParameter("Uid", pageRoot._pendingUid)
                            creationAccount.updateSignInCredentials("Jolla", "Jolla", sip, "")
                        }
                    }
                }

                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: !pageRoot._needsTwoFA
                    //% "Sign in"
                    text: qsTr("Sign in")
                    enabled: !pageRoot._busy
                            && usernameField.text.length > 0
                            && passwordField.text.length > 0
                    onClicked: {
                        pageRoot._errorMessage = ""
                        pageRoot._busy = true
                        root.delayDeletion = true
                        pageRoot._pendingUsername = usernameField.text
                        pageRoot._pendingPassword = passwordField.text
                        console.log("proton: Sign in clicked, stored pending username=" + pageRoot._pendingUsername + " pw_len=" + pageRoot._pendingPassword.length)
                        accountManager.createAccount(root.accountProvider.name)
                    }
                }

                BusyIndicator {
                    anchors.horizontalCenter: parent.horizontalCenter
                    running: pageRoot._busy
                    visible: pageRoot._busy
                }

                Label {
                    visible: pageRoot._errorMessage.length > 0
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    color: Theme.errorColor
                    font.pixelSize: Theme.fontSizeSmall
                    wrapMode: Text.Wrap
                    text: pageRoot._errorMessage
                }
            }
        }
    }

    AccountManager {
        id: accountManager

        onAccountCreated: {
            if (providerName == root.accountProvider.name) {
                creationAccount.identifier = accountId
            }
        }
        onAccountCreationFailed: {
            if (providerName == root.accountProvider.name) {
                root._fail(message)
            }
        }
    }

    Account {
        id: creationAccount

        property bool _credentialsRequested
        property bool _flowComplete

        onStatusChanged: {
            console.log("proton: statusChanged status=" + status + " Account.Initialized=" + Account.Initialized + " Initializing=" + Account.Initializing + " Invalid=" + Account.Invalid + " SyncInProgress=" + Account.SyncInProgress + " Synced=" + Account.Synced + " SigningIn=" + Account.SigningIn + " Error=" + Account.Error + " _flowComplete=" + _flowComplete + " _busy=" + pageRoot._busy + " id=" + identifier + " hasCreds=" + hasSignInCredentials("Jolla","Jolla"))
            if (status == Account.Initialized && pageRoot._busy
                    && !_credentialsRequested && !pageRoot._needsTwoFA) {
                _credentialsRequested = true
                // Store pending credentials for OTP second step (fields become hidden)
                // Password is passed as transient "Password" param, NOT as Secret, so it is never stored in signond
                if (pageRoot._pendingUsername === "" ) pageRoot._pendingUsername = usernameField.text
                if (pageRoot._pendingPassword === "" ) pageRoot._pendingPassword = passwordField.text
                console.log("proton: creating credentials for " + pageRoot._pendingUsername + " pw_len=" + pageRoot._pendingPassword.length)
                // Use dummy "x" for Secret (stored) and real password as transient "Password" param
                // so raw password is never persisted (empty Secret with symmetricKey="" triggers isNull() error)
                var sip = signInParameters("proton-carddav", pageRoot._pendingUsername, "x")
                sip.setParameter("Password", pageRoot._pendingPassword)
                console.log("proton: sip username=" + sip.username + " password_len=" + (sip.password ? sip.password.length : 0) + " hasPasswordParam set")
                createSignInCredentials("Jolla", "Jolla", sip, "")
            } else if (status == Account.Synced && _flowComplete) {
                // Credentials verified (OTP included when needed) and the
                // account settings saved: done. Note: setStatus(Synced) is
                // emitted BEFORE signInCredentialsCreated/Updated, so the
                // completion is driven by _flowComplete instead of the
                // credentials signals alone.
                pageRoot._busy = false
                root.delayDeletion = false
                console.log("proton: flow complete, emitting accountCreated id=" + identifier)
                root.accountCreated(identifier)
                root.goToEndDestination()
            } else if (status == Account.Error) {
                root._fail(errorMessage)
            }
        }

        onSignInCredentialsCreated: {
            console.log("proton: onSignInCredentialsCreated data=" + JSON.stringify(data))
            if (data["TwoFARequired"] === true) {
                // Locked session: reveal the OTP field and wait for the code.
                console.log("proton: TwoFARequired, pending tokens present: AccessToken=" + (data["AccessToken"] ? "yes" : "no"))
                _credentialsRequested = false
                pageRoot._pendingAccessToken = data["AccessToken"] || ""
                pageRoot._pendingRefreshToken = data["RefreshToken"] || ""
                pageRoot._pendingUid = data["Uid"] || ""
                pageRoot._needsTwoFA = true
                pageRoot._busy = false
                otpField.forceActiveFocus()
            } else {
                // Fully authenticated: enable and save the account; the
                // Account.Synced status completes the flow.
                _flowComplete = true
                root.delayDeletion = true
                enabled = true
                enableWithService("proton-carddav")
                setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
                setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
                var globalSettings = configurationValues("")
                var debugLines = ["global settings:"]
                for (var gk in globalSettings) {
                    debugLines.push(gk + "=" + globalSettings[gk])
                }
                var identityId = globalSettings["Jolla/segregated_credentials/Jolla"]
                debugLines.push("identityId=" + identityId)
                _writeDebug(debugLines.join("\n"))
                if (identityId !== undefined && parseInt(identityId) !== 0) {
                    root._setCredentialsId(identityId)
                } else {
                    console.log("proton: WARNING no identityId found for CredentialsId")
                }
                sync()
            }
        }

        onSignInCredentialsUpdated: {
            // OTP verified (2FA pass via updateSignInCredentials). Enable
            // and save the account; Account.Synced completes the flow.
            console.log("proton: onSignInCredentialsUpdated data=" + JSON.stringify(data))
            _flowComplete = true
            root.delayDeletion = true
            enabled = true
            enableWithService("proton-carddav")
            setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
            setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
            var globalSettings = configurationValues("")
            var debugLines = ["proton: global settings in update:"]
            for (var gk in globalSettings) {
                debugLines.push(gk + "=" + globalSettings[gk])
            }
            _writeDebug(debugLines.join("\n"))
            var identityId = configurationValue("", "Jolla/segregated_credentials/Jolla")
            if (identityId === undefined || parseInt(identityId) === 0) {
                identityId = globalSettings["Jolla/segregated_credentials/Jolla"]
            }
            console.log("proton: update identityId=" + identityId + " type=" + typeof identityId)
            if (identityId !== undefined && parseInt(identityId) !== 0) {
                var ok = root._setCredentialsId(identityId)
                console.log("proton: _setCredentialsId returned " + ok)
                console.log("proton: after set global CredentialsId=" + configurationValue("", "CredentialsId"))
                console.log("proton: after set service CredentialsId=" + configurationValue("proton-carddav", "CredentialsId"))
            } else {
                console.log("proton: WARNING no identityId in update, globalSettings dump above")
            }
            console.log("proton: calling sync() for OTP update")
            sync()
        }

        onSignInError: {
            if (pageRoot._needsTwoFA) {
                // Wrong code: let the user retry in the OTP field.
                pageRoot._busy = false
                // Keep delayDeletion true so agent stays alive for retry
                pageRoot._errorMessage = message
            } else {
                root._fail(message)
            }
        }
    }
}
