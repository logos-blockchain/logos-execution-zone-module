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
    Q_INVOKABLE WalletFfiError create_account_public(FfiBytes32* out_account_id) override;
    Q_INVOKABLE WalletFfiError create_account_private(FfiBytes32* out_account_id) override;
    Q_INVOKABLE WalletFfiError list_accounts(FfiAccountList* out_list) override;

    // Account Queries
    Q_INVOKABLE WalletFfiError get_balance(
        const FfiBytes32* account_id,
        bool is_public,
        QByteArray* out_balance_le16
    ) override;
    Q_INVOKABLE WalletFfiError
    get_account_public(const FfiBytes32* account_id, FfiAccount* out_account) override;
    Q_INVOKABLE WalletFfiError
    get_account_private(const FfiBytes32* account_id, FfiAccount* out_account) override;
    Q_INVOKABLE WalletFfiError get_public_account_key(
        const FfiBytes32* account_id,
        FfiPublicAccountKey* out_public_key
    ) override;
    Q_INVOKABLE WalletFfiError get_private_account_keys(
        const FfiBytes32* account_id,
        FfiPrivateAccountKeys* out_keys
    ) override;

    // Account Encoding
    Q_INVOKABLE QString account_id_to_base58(const FfiBytes32* account_id) override;
    Q_INVOKABLE WalletFfiError account_id_from_base58(const QString& base58_str, FfiBytes32* out_account_id) override;

    // Blockchain Synchronisation
    Q_INVOKABLE WalletFfiError sync_to_block(uint64_t block_id) override;
    Q_INVOKABLE WalletFfiError get_last_synced_block(uint64_t* out_block_id) override;
    Q_INVOKABLE WalletFfiError get_current_block_height(uint64_t* out_block_height) override;

    // Operations
    Q_INVOKABLE WalletFfiError transfer_public(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError transfer_shielded(
        const FfiBytes32* from,
        const FfiPrivateAccountKeys* to_keys,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError transfer_deshielded(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError transfer_private(
        const FfiBytes32* from,
        const FfiPrivateAccountKeys* to_keys,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError transfer_shielded_owned(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError transfer_private_owned(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) override;
    Q_INVOKABLE WalletFfiError
    register_public_account(const FfiBytes32* account_id, FfiTransferResult* out_result) override;
    Q_INVOKABLE WalletFfiError
    register_private_account(const FfiBytes32* account_id, FfiTransferResult* out_result) override;

    // Wallet Lifecycle
    Q_INVOKABLE WalletFfiError create_new(
        const QString& config_path,
        const QString& storage_path,
        const QString& password
    ) override;
    Q_INVOKABLE WalletFfiError open(const QString& config_path, const QString& storage_path) override;
    Q_INVOKABLE WalletFfiError save() override;

    // Configuration
    Q_INVOKABLE QString get_sequencer_addr() override;

signals:
    void eventResponse(const QString& eventName, const QVariantList& data);
};

#endif
