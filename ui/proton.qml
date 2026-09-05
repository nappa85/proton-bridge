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
        if (creationAccount.identifier > 0 && !pageRoot._needsTwoFA) {
            var id = creationAccount.identifier
            creationAccount.identifier = 0
            var acc = accountManager.account(id)
            if (acc) acc.remove()
        }
    }

    initialPage: Page {
        id: pageRoot

        property bool _busy
        property string _errorMessage
        property bool _needsTwoFA
        property string _pendingAccessToken
        property string _pendingRefreshToken
        property string _pendingUid

        backNavigation: !_busy

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
                            var sip = creationAccount.signInParameters("proton-carddav",
                                                                      usernameField.text,
                                                                      passwordField.text)
                            sip.setParameter("TwoFactorPassword", otpField.text)
                            sip.setParameter("AccessToken", pageRoot._pendingAccessToken)
                            sip.setParameter("RefreshToken", pageRoot._pendingRefreshToken)
                            sip.setParameter("Uid", pageRoot._pendingUid)
                            creationAccount.updateSignInCredentials("Jolla", "Jolla", sip)
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
            if (status == Account.Initialized && pageRoot._busy
                    && !_credentialsRequested && !pageRoot._needsTwoFA) {
                _credentialsRequested = true
                var sip = signInParameters("proton-carddav", usernameField.text, passwordField.text)
                createSignInCredentials("Jolla", "Jolla", sip)
            } else if (status == Account.Synced && _flowComplete) {
                // Credentials verified (OTP included when needed) and the
                // account settings saved: done. Note: setStatus(Synced) is
                // emitted BEFORE signInCredentialsCreated/Updated, so the
                // completion is driven by _flowComplete instead of the
                // credentials signals alone.
                pageRoot._busy = false
                root.accountCreated(identifier)
                pageStack.pop()
            } else if (status == Account.Error) {
                root._fail(errorMessage)
            }
        }

        onSignInCredentialsCreated: {
            if (data["TwoFARequired"] === true) {
                // Locked session: reveal the OTP field and wait for the code.
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
                enabled = true
                enableWithService("proton-carddav")
                setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
                setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
                // Link the signon identity to the service: the buteo sync
                // plugin reads authData().credentialsId(), which maps to the
                // per-service "CredentialsId" account setting. The identity
                // id was stored by createSignInCredentials under the
                // segregated credentials key.
                var globalSettings = configurationValues("")
                var debugLines = ["global settings:"]
                for (var gk in globalSettings) {
                    debugLines.push(gk + "=" + globalSettings[gk])
                }
                var identityId = globalSettings["Jolla/segregated_credentials/Jolla"]
                debugLines.push("identityId=" + identityId)
                _writeDebug(debugLines.join("\n"))
                if (identityId !== undefined && identityId !== 0) {
                    setConfigurationValue("", "CredentialsId", identityId)
                    setConfigurationValue("proton-carddav", "CredentialsId", identityId)
                }
                sync()
            }
        }

        onSignInCredentialsUpdated: {
            // OTP verified (2FA pass via updateSignInCredentials). Enable
            // and save the account; Account.Synced completes the flow.
            _flowComplete = true
            enabled = true
            enableWithService("proton-carddav")
            setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
            setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
            var globalSettings = configurationValues("")
            var identityId = globalSettings["Jolla/segregated_credentials/Jolla"]
            if (identityId !== undefined) {
                setConfigurationValue("proton-carddav", "CredentialsId", identityId)
            }
            sync()
        }

        onSignInError: {
            if (pageRoot._needsTwoFA) {
                // Wrong code: let the user retry in the OTP field.
                pageRoot._busy = false
                pageRoot._errorMessage = message
            } else {
                root._fail(message)
            }
        }
    }
}
