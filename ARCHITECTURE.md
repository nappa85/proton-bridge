# Buteo Sync Plugin Architecture - Reference Document

## How Buteo Sync Plugins Work

### Plugin Discovery & Loading

`PluginManager` (`libbuteosyncfw/pluginmgr/PluginManager.cpp`) scans two directories:

1. **In-process**: `$$[QT_INSTALL_LIBS]/buteo-plugins-qt5/` (e.g. `/usr/lib64/buteo-plugins-qt5/`)
2. **Out-of-process (OOP)**: `$$[QT_INSTALL_LIBS]/buteo-plugins-qt5/oopp/`

It looks for `.so` files ending in `-client.so`, `-server.so`, `-storage.so`, etc.
The plugin name is derived by:
- Stripping the `-client.so` suffix (11 chars)
- Stripping the `lib` prefix (3 chars)

Example: `libcarddav-client.so` → plugin name `carddav`

OOP plugins in the `oopp/` subdirectory are loaded into `iOopClientMaps`.

### Sync Trigger Flow (Manual)

```
startSync(profileName)         # D-Bus call from user/Settings app
  └─ startSync(name, false)    # false = not scheduled
       ├─ Check backup/restore not in progress
       ├─ Load profile from ProfileManager
       ├─ Check profile exists
       ├─ Check profile.isEnabled()
       ├─ Check profile.isValid()
       ├─ Check no same-type sync already running
       ├─ Reserve storages
       └─ startSyncNow(session)
            ├─ Get clientProfile = profile->clientProfile()
            ├─ Create ClientPluginRunner(clientProfile->name(), ...)
            ├─ runner.init()
            │    └─ PluginManager::createClient(pluginName, profile, cbInterface)
            │         ├─ Look up pluginName in iClientMaps (in-process)
            │         └─ OR look up pluginName in iOopClientMaps (OOP)
            │              └─ startOOPPlugin(pluginName, profileName, libraryPath)
            │                   ├─ Launch: /usr/libexec/buteo-oopp-runner <pluginName> <profileName> <libraryPath>
            │                   ├─ Wait up to 30s for D-Bus registration
            │                   └─ Create OOPClientPlugin (D-Bus proxy to the runner process)
            └─ session.start()
                 └─ OOPClientPlugin::init() → D-Bus call to oopp-runner → loads .so via QPluginLoader
                      └─ PluginServiceObj::init() → QPluginLoader::instance() → qobject_cast<SyncPluginLoader*>
                           └─ syncPluginLoader->createClientPlugin(pluginName, syncProfile, cb)
                                └─ Our ProtonContactsPlugin is created and init() is called
```

**CRITICAL**: Manual `startSync()` does NOT check connectivity. Only `startScheduledSync()` does.
The `isConnectivityAvailable` D-Bus method is informational, not a gate for manual syncs.

### OOP Plugin Architecture

The oopp-runner (`/usr/libexec/buteo-oopp-runner`) is a separate process that:

1. Takes 3 cmdline args: `pluginName`, `profileName`, `pluginFilePath`
2. Loads the plugin .so via `QPluginLoader(pluginFilePath)`
3. `qobject_cast<SyncPluginLoader*>(pluginLoader->instance())` - this requires:
   - The .so is a valid Qt plugin (built with `Q_PLUGIN_METADATA`)
   - The class implements `Buteo::SyncPluginLoader` (via `Q_INTERFACES`)
4. Creates the `ClientPlugin` via `syncPluginLoader->createClientPlugin()`
5. Registers on D-Bus as `com.buteo.msyncd.plugin.<profileName>`
6. Relays all plugin signals (success/error/transferProgress) via D-Bus

The `OOPClientPlugin` (in msyncd process) is a D-Bus proxy that:
- Forwards `init()`, `startSync()`, `abortSync()` etc. to the runner
- Relays signals back from the runner to msyncd

### Account & Profile Creation Flow

When a user adds a Proton account in Settings:

1. Accounts UI creates an `Accounts::Account` with provider `proton`
2. `AccountsHelper` receives `accountCreated(accountId)` signal
3. `createProfileForAccount()` is called:
   - Gets the account's service list (from `proton-carddav.service`)
   - For each service, looks up a sync profile template by service name
   - `addProfileForAccount()` clones the template, sets name to `<serviceName>-<accountId>`
   - Sets `KEY_ACCOUNT_ID` to the account ID
   - Stores the profile

The service XML (`proton-carddav.service`) contains `sync_profile_templates=["proton.Contacts"]`
which tells the framework to look for the template `proton.Contacts.xml`.

### How CardDAV Gets Credentials

The CardDAV `Auth` class (`auth.cpp`):

1. `Accounts::Account::fromId(&manager, accountId, this)` - load account
2. Find service with `serviceType() == "carddav"` 
3. `Accounts::AccountService(account, service)` - get account-service
4. Read `server_address` from account settings
5. `accSrv.authData().credentialsId()` → get SignOn identity ID
6. `SignOn::Identity::existingIdentity(credentialsId)` 
7. `identity->createSession(method)` → create auth session
8. `session->process(sessionData, mechanism)` → triggers SignOn
9. Response contains `username`, `password` (or `accessToken`)

## What Was Wrong With Our Implementation

### Issue 1: Manual sync was NOT blocked by connectivity

We spent time debugging `isConnectivityAvailable` returning `false`, but this is
ONLY checked for scheduled syncs (`startScheduledSync`). Manual `startSync()` 
never checks connectivity. The `false` return from `startSync()` was caused by
something else entirely.

### Issue 2: The .so may not be a valid Qt plugin

Our build compiles the .so manually with `-shared -fPIC` but does NOT use
qmake's `CONFIG += plugin`. The `Q_PLUGIN_METADATA` macro requires the moc
output to be compiled and linked, which we do, BUT:

- Qt's `CONFIG += plugin` adds `-DQT_PLUGIN` which may affect behavior
- The linker flags may differ from what qmake produces for a plugin
- The `QPluginLoader` may fail to load the .so if the plugin metadata
  section is not properly created

### Issue 3: Profile naming vs .so naming

The client sub-profile name in the sync profile XML determines which .so
is loaded. The `loadPluginMaps` function maps filenames to plugin names:

- `libproton-contacts-client.so` → maps to `proton-contacts`
- `libproton-client.so` → maps to `proton`

The client profile name must match the .so-derived name:
- CardDAV: profile name `carddav` = .so name `carddav` (from `libcarddav-client.so`)
- Ours: profile name `proton-contacts` = .so name `proton-contacts` (from `libproton-contacts-client.so`)

This matches, but we deployed multiple conflicting .so files.

### Issue 4: Accounts DB permission issues

On the expendable phone (no SMACK), the accounts DB directory has wrong ownership.
`AccountsHelper::createProfileForAccount()` uses `Accounts::Manager` which needs
access to `/home/defaultuser/.local/share/system/privileged/Accounts/`. When it
can't access this, `getProfilesByAccountId()` returns empty, so `start(accountId)`
does nothing.

### Issue 5: The `start()` D-Bus method doesn't return success/failure

`Synchronizer::start(uint accountId)` returns `void`, not `bool`. So when we
called `start(2)` via D-Bus, it appeared to "succeed" but actually did nothing
because `getProfilesByAccountId(2)` returned empty.

## Reference: CardDAV Plugin Structure

```
buteo-sync-plugin-carddav/
├── src/
│   ├── carddavclient.h         - Proxies ClientPlugin
│   ├── carddavclient.cpp       - init/startSync/abortSync
│   ├── CardDavClientLoader     - Q_PLUGIN_METADATA + SyncPluginLoader
│   ├── syncer.cpp              - TwoWayContactSyncAdaptor, does actual sync
│   ├── auth.cpp                - Accounts/SignOn credential flow
│   ├── carddav.cpp             - HTTP CardDAV protocol
│   ├── carddav.xml             - Client profile template
│   └── carddav.Contacts.xml    - Sync profile template
├── buteo-sync-plugin-carddav.pro
└── rpm/buteo-sync-plugin-carddav.spec
```

Key observations from CardDAV:
- Uses `Q_PLUGIN_METADATA(IID "org.sailfishos.plugins.sync.CardDavClientLoader")`
- Uses `Q_INTERFACES(Buteo::SyncPluginLoader)` 
- `.so` is `libcarddav-client.so` → plugin name `carddav`
- Client profile name is `carddav`, Sync Protocol is `carddav` - ALL MATCH
- Sync profile has NO `<conditions>` block
- `enabled=false`, `hidden=true` in template (overridden per-account)
- Auth happens in `startSync()`, not in `init()`
- Uses `TwoWayContactSyncAdaptor` for proper two-way sync

## Fix Plan

1. **Use qmake build system** for the C++ plugin (like CardDAV does)
   - Create a .pro file with `CONFIG += plugin`
   - Let qmake handle moc, linking, etc.
   - This ensures the .so is a proper Qt plugin

2. **Consistent naming**: 
   - `.so` name = `libproton-client.so` → plugin name `proton`
   - Client profile name = `proton`
   - Sync Protocol key = `proton`
   - OR keep `proton-contacts` everywhere consistently

3. **Remove `<conditions>` from sync profile** (already done but verify)

4. **Test plugin loading independently**: Run `buteo-oopp-runner` manually
   to verify the .so loads as a Qt plugin before testing via msyncd

5. **Fix accounts DB permissions** on the phone before testing `start(accountId)`

6. **Auth in startSync, not init**: Follow CardDAV's pattern of requesting
   credentials in `startSync()` rather than `init()`

7. **Debug logging**: Use Qt's logging categories (like CardDAV's `lcCardDav`)
   instead of file-based logging, since the OOP runner's output goes to
   the journal or is forwarded by msyncd
