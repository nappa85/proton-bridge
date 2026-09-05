#pragma once

#include <SignOn/authpluginif.h>
#include "proton_bridge.h"

class ProtonSignonPlugin : public AuthPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(AuthPluginInterface)

public:
    ProtonSignonPlugin(QObject *parent = nullptr);
    ~ProtonSignonPlugin() override;

    QString type() const override;
    QStringList mechanisms() const override;
    void cancel() override;
    void process(const SignOn::SessionData &inData, const QString &mechanism = QString()) override;
    void userActionFinished(const SignOn::UiSessionData &data) override;
    void refresh(const SignOn::UiSessionData &data) override;

private:
    void handleAuthOk(ProtonAuthResult &authResult,
                      const QString &username,
                      const QString &password);
};
