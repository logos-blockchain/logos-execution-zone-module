#ifndef LOGOS_EXECUTION_ZONE_WALLET_MODULE_H
#define LOGOS_EXECUTION_ZONE_WALLET_MODULE_H

#include "i_logos_execution_zone_wallet_module.h"

#include <QObject>
#include <QString>
#include <QVariantList>

class LogosExecutionZoneWalletModule : public QObject, public PluginInterface, public ILogosExecutionZoneWalletModule {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID ILogosExecutionZoneWalletModule_iid FILE LOGOS_EXECUTION_ZONE_WALLET_MODULE_METADATA_FILE)
    Q_INTERFACES(PluginInterface ILogosExecutionZoneWalletModule)

private:
    LogosAPI* logosApi = nullptr;
    WalletHandle* walletHandle = nullptr;

public:
    LogosExecutionZoneWalletModule();
    ~LogosExecutionZoneWalletModule() override;

    // === Plugin Interface ===
    [[nodiscard]] QString name() const override;
    [[nodiscard]] QString version() const override;

    //  === Logos Core ===

    Q_INVOKABLE void initLogos(LogosAPI* logosApiInstance) override;

    //  === Logos Execution Zone Wallet  ===

    // Account Management
    Q_INVOKABLE WalletFfiError create_account_public(QString& output_account_id_hex) override;
    Q_INVOKABLE WalletFfiError create_account_private(QString& output_account_id_hex) override;
    Q_INVOKABLE WalletFfiError list_accounts(QJsonArray& output_list) override;

    // Account Queries
    Q_INVOKABLE WalletFfiError
    get_balance(const QString& account_id_hex, bool is_public, QString& output_balance_le16_hex) override;
    Q_INVOKABLE WalletFfiError get_account_public(const QString& account_id_hex, QString& output_account_json) override;
    Q_INVOKABLE WalletFfiError
    get_account_private(const QString& account_id_hex, QString& output_account_json) override;
    Q_INVOKABLE WalletFfiError
    get_public_account_key(const QString& account_id_hex, QString& output_public_key_hex) override;
    Q_INVOKABLE WalletFfiError
    get_private_account_keys(const QString& account_id_hex, QString& output_keys_json) override;

    // Account Encoding
    Q_INVOKABLE QString account_id_to_base58(const QString& account_id_hex) override;
    Q_INVOKABLE WalletFfiError
    account_id_from_base58(const QString& base58_str, QString& output_account_id_hex) override;

    // Blockchain Synchronisation
    Q_INVOKABLE WalletFfiError sync_to_block(uint64_t block_id) override;
    Q_INVOKABLE WalletFfiError get_last_synced_block(uint64_t* output_block_id) override;
    Q_INVOKABLE WalletFfiError get_current_block_height(uint64_t* output_block_height) override;

    // Operations
    Q_INVOKABLE WalletFfiError transfer_public(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError transfer_shielded(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError transfer_deshielded(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError transfer_private(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError transfer_shielded_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError transfer_private_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) override;
    Q_INVOKABLE WalletFfiError
    register_public_account(const QString& account_id_hex, QString& output_result_json) override;
    Q_INVOKABLE WalletFfiError
    register_private_account(const QString& account_id_hex, QString& output_result_json) override;

    // Wallet Lifecycle
    Q_INVOKABLE WalletFfiError
    create_new(const QString& config_path, const QString& storage_path, const QString& password) override;
    Q_INVOKABLE WalletFfiError open(const QString& config_path, const QString& storage_path) override;
    Q_INVOKABLE WalletFfiError save() override;

    // Configuration
    Q_INVOKABLE QString get_sequencer_addr() override;

signals:
    void eventResponse(const QString& eventName, const QVariantList& data);
};

#endif
