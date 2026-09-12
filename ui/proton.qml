import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0
// Unused import on purpose: loading the Proton extension runs its
// initializeEngine, which installs our .qm translator for this page.
import Proton 1.0

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
 *   3b. If the result contains CaptchaRequired (API 9001 human
 *      verification, usually network reputation), a message + the
 *      verification link + a retry button are revealed instead. Note:
 *      solving the challenge in an external browser does NOT continue
 *      the login here (the proof returns via postMessage to the embedding
 *      page) — the copy says so and suggests retrying from another
 *      network. The challenge token never lands in logs.
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
        if (creationAccount.identifier > 0 && !pageRoot._needsTwoFA && !pageRoot._needsCaptcha) {
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
        property bool _needsCaptcha
        property string _captchaUrl
        property string _captchaMethods
        property string _captchaToken
        property string _pendingAccessToken
        property string _pendingRefreshToken
        property string _pendingUid
        property string _pendingUsername
        property string _pendingPassword
        property bool _credentialsExist

        backNavigation: !_busy

        function _startSignIn() {
            if (pageRoot._pendingUsername === "") pageRoot._pendingUsername = usernameField.text
            if (pageRoot._pendingPassword === "") pageRoot._pendingPassword = passwordField.text
            var sip = creationAccount.signInParameters("proton-carddav", pageRoot._pendingUsername, "x")
            sip.setParameter("Password", pageRoot._pendingPassword)
            if (pageRoot._captchaToken.length > 0) {
                sip.setParameter("HumanVerificationToken", pageRoot._captchaToken)
            }
            if (pageRoot._credentialsExist) {
                console.log("proton: updating credentials for " + pageRoot._pendingUsername)
                creationAccount.updateSignInCredentials("Jolla", "Jolla", sip, "")
            } else {
                console.log("proton: creating credentials for " + pageRoot._pendingUsername)
                creationAccount.createSignInCredentials("Jolla", "Jolla", sip, "")
            }
        }

        on_BusyChanged: {
            if (_busy) root.delayDeletion = true
            else if (!_needsTwoFA && !_needsCaptcha && !creationAccount._flowComplete) root.delayDeletion = false
        }
        on_NeedsTwoFAChanged: {
            if (_needsTwoFA) root.delayDeletion = true
        }
        on_NeedsCaptchaChanged: {
            if (_needsCaptcha) root.delayDeletion = true
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
                    visible: !pageRoot._needsTwoFA && !pageRoot._needsCaptcha
                }

                PasswordField {
                    id: passwordField
                    enabled: !pageRoot._busy
                    visible: !pageRoot._needsTwoFA && !pageRoot._needsCaptcha
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
                            if (pageRoot._captchaToken.length > 0) {
                                sip.setParameter("HumanVerificationToken", pageRoot._captchaToken)
                            }
                            creationAccount.updateSignInCredentials("Jolla", "Jolla", sip, "")
                        }
                    }
                }

                Button {
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: !pageRoot._needsTwoFA && !pageRoot._needsCaptcha
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
                        pageRoot._captchaToken = ""
                        pageRoot._credentialsExist = false
                        console.log("proton: Sign in clicked, stored pending username=" + pageRoot._pendingUsername + " pw_len=" + pageRoot._pendingPassword.length)
                        accountManager.createAccount(root.accountProvider.name)
                    }
                }

                Column {
                    width: parent.width
                    spacing: Theme.paddingLarge
                    visible: pageRoot._needsCaptcha

                    Label {
                        //% "Proton blocked this sign-in attempt with a human-verification challenge (spam protection, usually triggered by the network)."
                        text: qsTr("Proton blocked this sign-in attempt with a human-verification challenge (spam protection, usually triggered by the network).")
                        wrapMode: Text.Wrap
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeSmall
                    }

                    Label {
                        //% "Offered verification methods: %1"
                        text: qsTr("Offered verification methods: %1").arg(pageRoot._captchaMethods)
                        wrapMode: Text.Wrap
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeSmall
                    }

                    Label {
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        wrapMode: Text.Wrap
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeSmall
                        //% "Open the verification page"
                        text: qsTr("Open the verification page")
                        font.underline: true

                        MouseArea {
                            anchors.fill: parent
                            onClicked: Qt.openUrlExternally(pageRoot._captchaUrl)
                        }
                    }

                    Label {
                        //% "After solving the verification in the browser, press Try again — the login will be retried with the verification token."
                        text: qsTr("After solving the verification in the browser, press Try again — the login will be retried with the verification token.")
                        wrapMode: Text.Wrap
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        color: Theme.highlightColor
                        font.pixelSize: Theme.fontSizeSmall
                    }

                    Button {
                        anchors.horizontalCenter: parent.horizontalCenter
                        //% "Try again"
                        text: qsTr("Try again")
                        enabled: !pageRoot._busy
                        onClicked: {
                            pageRoot._errorMessage = ""
                            pageRoot._busy = true
                            pageRoot._needsCaptcha = false
                            root.delayDeletion = true
                            creationAccount._credentialsRequested = false
                            if (pageRoot._needsTwoFA) {
                                // Captcha was on 2FA submit: retry 2FA with
                                // the HV token (not a full re-login).
                                var sip = creationAccount.signInParameters("proton-carddav",
                                                                            pageRoot._pendingUsername, "x")
                                sip.setParameter("Password", pageRoot._pendingPassword)
                                sip.setParameter("TwoFactorPassword", otpField.text)
                                sip.setParameter("AccessToken", pageRoot._pendingAccessToken)
                                sip.setParameter("RefreshToken", pageRoot._pendingRefreshToken)
                                sip.setParameter("Uid", pageRoot._pendingUid)
                                sip.setParameter("HumanVerificationToken", pageRoot._captchaToken)
                                creationAccount.updateSignInCredentials("Jolla", "Jolla", sip, "")
                            } else {
                                pageRoot._startSignIn()
                            }
                        }
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
                    && !_credentialsRequested && !pageRoot._needsTwoFA && !pageRoot._needsCaptcha) {
                _credentialsRequested = true
                // Store pending credentials for OTP second step (fields become hidden)
                // Password is passed as transient "Password" param, NOT as Secret, so it is never stored in signond
                pageRoot._startSignIn()
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
            pageRoot._credentialsExist = true
            console.log("proton: onSignInCredentialsCreated hasCaptcha=" + (data["CaptchaRequired"] === true) + " has2FA=" + (data["TwoFARequired"] === true))
            if (data["CaptchaRequired"] === true) {
                // Human-verification challenge: show message + link, keep
                // the agent alive for a retry. Never logs the URL (token).
                _credentialsRequested = false
                pageRoot._captchaMethods = data["CaptchaMethods"] || ""
                pageRoot._captchaUrl = data["CaptchaUrl"] || ""
                pageRoot._captchaToken = data["CaptchaToken"] || ""
                // If the challenge arrived during 2FA, preserve the locked-
                // session tokens so the retry can go straight to submit_2fa.
                if (data["TwoFARequired"] === true) {
                    pageRoot._pendingAccessToken = data["AccessToken"] || pageRoot._pendingAccessToken
                    pageRoot._pendingRefreshToken = data["RefreshToken"] || pageRoot._pendingRefreshToken
                    pageRoot._pendingUid = data["Uid"] || pageRoot._pendingUid
                    pageRoot._needsTwoFA = true
                } else {
                    pageRoot._needsTwoFA = false
                }
                pageRoot._needsCaptcha = true
                pageRoot._busy = false
            } else if (data["TwoFARequired"] === true) {
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
                enableWithService("proton-caldav")
                setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
                setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
                setConfigurationValue("proton-caldav", "server_address", "https://mail.proton.me")
                setConfigurationValue("proton-caldav", "ignore_ssl_errors", false)
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
            // OTP verified (2FA pass via updateSignInCredentials) — unless
            // the server answered THAT with a challenge instead.
            console.log("proton: onSignInCredentialsUpdated hasCaptcha=" + (data["CaptchaRequired"] === true))
            if (data["CaptchaRequired"] === true) {
                pageRoot._captchaMethods = data["CaptchaMethods"] || ""
                pageRoot._captchaUrl = data["CaptchaUrl"] || ""
                pageRoot._captchaToken = data["CaptchaToken"] || ""
                // Preserve 2FA state if the challenge arrived on submit_2fa.
                if (data["TwoFARequired"] === true) {
                    pageRoot._pendingAccessToken = data["AccessToken"] || pageRoot._pendingAccessToken
                    pageRoot._pendingRefreshToken = data["RefreshToken"] || pageRoot._pendingRefreshToken
                    pageRoot._pendingUid = data["Uid"] || pageRoot._pendingUid
                    pageRoot._needsTwoFA = true
                } else {
                    pageRoot._needsTwoFA = false
                }
                pageRoot._needsCaptcha = true
                pageRoot._busy = false
                return
            }
            if (data["TwoFARequired"] === true) {
                console.log("proton: onSignInCredentialsUpdated TwoFARequired")
                _credentialsRequested = false
                pageRoot._pendingAccessToken = data["AccessToken"] || ""
                pageRoot._pendingRefreshToken = data["RefreshToken"] || ""
                pageRoot._pendingUid = data["Uid"] || ""
                pageRoot._needsTwoFA = true
                pageRoot._busy = false
                otpField.forceActiveFocus()
                return
            }
            console.log("proton: onSignInCredentialsUpdated data=" + JSON.stringify(data))
            _flowComplete = true
            root.delayDeletion = true
            enabled = true
            enableWithService("proton-carddav")
            enableWithService("proton-caldav")
            setConfigurationValue("proton-carddav", "server_address", "https://mail.proton.me")
            setConfigurationValue("proton-carddav", "ignore_ssl_errors", false)
            setConfigurationValue("proton-caldav", "server_address", "https://mail.proton.me")
            setConfigurationValue("proton-caldav", "ignore_ssl_errors", false)
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
            if (pageRoot._needsTwoFA || pageRoot._needsCaptcha) {
                // Wrong code / failed retry: let the user retry in place.
                pageRoot._busy = false
                // Keep delayDeletion true so agent stays alive for retry
                pageRoot._errorMessage = message
            } else {
                root._fail(message)
            }
        }
    }
}
