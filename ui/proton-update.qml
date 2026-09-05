import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0

/*
 * Proton credentials update.
 *
 * The stock OnlineSyncAccountCredentialsUpdater is not used because:
 *  - the OTP code is collected in this page rather than through signon-ui
 *    (the in-process entry dialog of this jolla-signon-ui build crashes
 *    with SIGSEGV); the "proton" SignOn plugin returns a TwoFARequired
 *    result carrying the locked-session tokens and this UI completes the
 *    update with the code the user typed;
 *  - Proton has no WebDAV endpoint to validate against, so the generic HTTP
 *    check performed by the stock updater is skipped: the "proton" SignOn
 *    plugin itself validates the credentials (and handles the OTP when
 *    required).
 *
 * The page stays on screen for the whole flow.
 */
AccountCredentialsAgent {
    id: root

    canCancelUpdate: true
    // Keep agent alive while busy or waiting for OTP
    delayDeletion: updatePage ? (updatePage._busy || updatePage._needsTwoFA) : false

    initialPage: Page {
        id: updatePage

        property bool _busy
        property string _errorMessage
        property bool _needsTwoFA
        property string _pendingAccessToken
        property string _pendingRefreshToken
        property string _pendingUid
        property string _pendingPassword

        backNavigation: !_busy

        function _update(extraParams) {
            _errorMessage = ""
            _busy = true
            // Password is passed as transient "Password" param, not as Secret, so raw password is never persisted
            // Use dummy "x" for Secret to avoid isNull() encryption error
            if (!extraParams && passwordField.text.length > 0) {
                _pendingPassword = passwordField.text
            }
            var sip = account.signInParameters("proton-carddav",
                                                account.defaultCredentialsUserName,
                                                "x")
            sip.setParameter("Password", _pendingPassword)
            if (extraParams) {
                for (var key in extraParams) {
                    sip.setParameter(key, extraParams[key])
                }
            }
            console.log("proton-update: _update pw_len=" + _pendingPassword.length + " extra=" + (extraParams ? JSON.stringify(extraParams) : "null") + " sip pw_len=" + (sip.password ? sip.password.length : 0))
            account.updateSignInCredentials("Jolla", "Jolla", sip, "")
        }

        SilicaFlickable {
            anchors.fill: parent
            contentHeight: header.height + summary.height + column.height + Theme.paddingLarge

            PageHeader {
                id: header
                //: Sign in to the account
                title: qsTrId("components_accounts-he-sign_in")
            }

            Item {
                id: summary
                anchors { top: header.bottom; left: parent.left; right: parent.right }
                height: Theme.iconSizeLarge + Theme.paddingLarge

                Image {
                    id: providerIcon
                    anchors { top: parent.top; left: parent.left; leftMargin: Theme.horizontalPageMargin }
                    width: Theme.iconSizeLarge
                    height: width
                    source: root.accountProvider.iconName
                }
                Column {
                    anchors {
                        left: providerIcon.right
                        leftMargin: Theme.paddingLarge
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        verticalCenter: parent.verticalCenter
                    }
                    Label {
                        width: parent.width
                        color: Theme.highlightColor
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeLarge
                        text: root.accountProvider.displayName
                    }
                    Label {
                        width: parent.width
                        visible: account.defaultCredentialsUserName.length > 0
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.secondaryHighlightColor
                        text: account.defaultCredentialsUserName
                    }
                }
            }

            Column {
                id: column
                anchors { top: summary.bottom; left: parent.left; right: parent.right }
                spacing: Theme.paddingLarge

                Label {
                    //: Shown when sign-in credentials need to be refreshed
                    //% "Sign in to refresh credentials"
                    text: qsTrId("components_accounts-la-sign_in_to_refresh_credentials")
                    wrapMode: Text.Wrap
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    color: Theme.secondaryHighlightColor
                }

                PasswordField {
                    id: passwordField
                    enabled: !updatePage._busy
                    visible: !updatePage._needsTwoFA
                    EnterKey.iconSource: "image://theme/icon-m-enter-close"
                    EnterKey.onClicked: signInButton.clicked()
                }

                Button {
                    id: signInButton
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: !updatePage._needsTwoFA
                    //% "Sign in"
                    text: qsTr("Sign in")
                    enabled: !updatePage._busy && passwordField.text.length > 0
                    onClicked: updatePage._update(null)
                }

                Column {
                    width: parent.width
                    spacing: Theme.paddingLarge
                    visible: updatePage._needsTwoFA

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
                        enabled: !updatePage._busy
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
                        enabled: !updatePage._busy && otpField.text.length == 6
                        onClicked: updatePage._update({
                            "TwoFactorPassword": otpField.text,
                            "AccessToken": updatePage._pendingAccessToken,
                            "RefreshToken": updatePage._pendingRefreshToken,
                            "Uid": updatePage._pendingUid
                        })
                    }
                }

                BusyIndicator {
                    anchors.horizontalCenter: parent.horizontalCenter
                    running: updatePage._busy
                    visible: updatePage._busy
                }

                Label {
                    visible: updatePage._errorMessage.length > 0
                    text: updatePage._errorMessage
                    color: Theme.errorColor
                    wrapMode: Text.Wrap
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                }
            }
        }
    }

    Account {
        id: account

        identifier: root.accountId

        onSignInCredentialsUpdated: {
            console.log("proton-update: onSignInCredentialsUpdated data=" + JSON.stringify(data))
            if (data["TwoFARequired"] === true) {
                // Locked session: reveal the OTP field and wait for the code.
                updatePage._pendingAccessToken = data["AccessToken"] || ""
                updatePage._pendingRefreshToken = data["RefreshToken"] || ""
                updatePage._pendingUid = data["Uid"] || ""
                updatePage._needsTwoFA = true
                updatePage._busy = false
                otpField.forceActiveFocus()
            } else {
                updatePage._busy = false
                root.credentialsUpdated(accountId)
                root.goToEndDestination()
            }
        }

        onSignInError: {
            if (updatePage._needsTwoFA) {
                // Wrong code: let the user retry in the OTP field.
                updatePage._busy = false
                updatePage._errorMessage = message
            } else {
                updatePage._busy = false
                updatePage._errorMessage = message
                root.credentialsUpdateError(message)
            }
        }
    }
}
