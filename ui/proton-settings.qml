// Proton account settings page.
//
// Fork of the stock OnlineSyncAccountSettingsAgent
// (/usr/share/accounts/ui/OnlineSyncAccountSettingsAgent.qml): identical
// structure and behavior, plus one pulley-menu item that explicitly purges
// synced data (contacts collection + mKCal notebooks) for this account via
// the Proton 1.0 QML extension. A fork is needed because the stock agent
// offers no hook for extra menu items, and our calendar service must not
// use stock CalDAV discovery flows.

import QtQuick 2.6
import Sailfish.Silica 1.0
import Sailfish.Accounts 1.0
import com.jolla.settings.accounts 1.0
import Proton 1.0

AccountSettingsAgent {
    id: root

    property var services: [
        accountManager.service("proton-carddav"),
        accountManager.service("proton-caldav")
    ]
    property var sharedScheduleServices: [
        accountManager.service("proton-carddav"),
        accountManager.service("proton-caldav")
    ]

    initialPage: Page {
        onPageContainerChanged: {
            if (pageContainer == null && !credentialsUpdater.running) {
                root.delayDeletion = true
                settingsDisplay.saveAccount()
            }
        }

        Component.onDestruction: {
            if (status == PageStatus.Active) {
                // app closed while settings are open, so save settings synchronously
                settingsDisplay.saveAccount(true)
            }
        }

        SilicaFlickable {
            anchors.fill: parent
            contentHeight: header.height + settingsDisplay.height + Theme.paddingLarge

            StandardAccountSettingsPullDownMenu {
                onCredentialsUpdateRequested: {
                    credentialsUpdater.replaceWithCredentialsUpdatePage(root.accountId)
                }
                onAccountDeletionRequested: {
                    root.accountDeletionRequested()
                    pageStack.pop()
                }
                onSyncRequested: {
                    settingsDisplay.saveAccountAndSync()
                }

                MenuItem {
                    //% "Advanced settings"
                    text: qsTrId("components_accounts-la-advanced_settings")

                    onClicked: {
                        pageStack.animatorPush(advancedSettingsDialogComponent, {"title": text})
                    }
                }

                MenuItem {
                    // Explicit, user-confirmed purge of everything this
                    // account synced to the phone. The account itself and
                    // its server-side data are untouched; the next sync
                    // re-downloads everything.
                    text: "Delete synced data from phone"
                    onClicked: {
                        purgeRemorse.execute(
                            "Deleting synced data",
                            function() {
                                if (!purger.purgeData(root.accountId)) {
                                    console.log("Proton: purge reported failure, see /tmp/proton-sync-debug.log")
                                }
                            })
                    }
                }
            }

            PageHeader {
                id: header

                title: root.accountsHeaderText
            }

            OnlineSyncAccountSettingsDisplay {
                id: settingsDisplay

                anchors.top: header.bottom
                accountManager: root.accountManager
                accountProvider: root.accountProvider
                accountId: root.accountId
                services: root.services
                sharedScheduleServices: root.sharedScheduleServices

                onAccountSaveCompleted: {
                    root.delayDeletion = false
                }
            }

            VerticalScrollDecorator {}
        }

        RemorsePopup {
            id: purgeRemorse
        }

        ProtonDataPurger {
            id: purger
        }

        AccountCredentialsUpdater {
            id: credentialsUpdater
        }
    }

    Component {
        id: advancedSettingsDialogComponent

        OnlineSyncAccountAdvancedSettingsDialog {
            account: settingsDisplay.account
            services: root.services

            onSettingsChanged: {
                settingsDisplay.saveAccount(true)

                // Reload the account settings from the saved values.
                settingsDisplay.reload(settingsDisplay.account.identifier)
            }
        }
    }
}
