#pragma once

#include "i_logos_execution_zone_wallet_module.h"

class LogosExecutionZoneWalletModule final : public QObject, public PluginInterface, public ILogosExecutionZoneWalletModule {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID ILogosExecutionZoneWalletModule_iid FILE LOGOS_EXECUTION_ZONE_WALLET_MODULE_METADATA_FILE)
    Q_INTERFACES(PluginInterface)

public:
    LogosExecutionZoneWalletModule();
    ~LogosExecutionZoneWalletModule() override;

    // Logos Core
    [[nodiscard]] QString name() const override;
    [[nodiscard]] QString version() const override;
    Q_INVOKABLE void initLogos(LogosAPI*) override;

    signals:
        void eventResponse(const QString& eventName, const QVariantList& data);
};
