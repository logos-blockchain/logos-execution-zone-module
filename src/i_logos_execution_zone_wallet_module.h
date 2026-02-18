#ifndef I_LOGOS_EXECUTION_ZONE_WALLET_MODULE_H
#define I_LOGOS_EXECUTION_ZONE_WALLET_MODULE_H

#include <core/interface.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <wallet_ffi.h>
#ifdef __cplusplus
}
#endif

class ILogosExecutionZoneWalletModule {
public:
    virtual ~ILogosExecutionZoneWalletModule() = default;

    // === Logos Core ===

    virtual void initLogos(LogosAPI* logosApiInstance) = 0;

    // === Logos Execution Zone Wallet ===

    // Account Management
    virtual WalletFfiError create_account_public(QString& output_account_id_hex) = 0;
    virtual WalletFfiError create_account_private(QString& output_account_id_hex) = 0;
    virtual WalletFfiError list_accounts(QJsonArray& output_list) = 0;

    // Account Queries
    virtual WalletFfiError get_balance(
        const QString& account_id_hex,
        bool is_public,
        QString& output_balance_le16_hex
    ) = 0;
    virtual WalletFfiError get_account_public(
        const QString& account_id_hex,
        QString& output_account_json
    ) = 0;
    virtual WalletFfiError get_account_private(
        const QString& account_id_hex,
        QString& output_account_json
    ) = 0;
    virtual WalletFfiError get_public_account_key(
        const QString& account_id_hex,
        QString& output_public_key_hex
    ) = 0;
    virtual WalletFfiError get_private_account_keys(
        const QString& account_id_hex,
        QString& output_keys_json
    ) = 0;

    // Account Encoding
    virtual QString account_id_to_base58(const QString& account_id_hex) = 0;
    virtual WalletFfiError account_id_from_base58(const QString& base58_str, QString& output_account_id_hex) = 0;

    // Blockchain Synchronisation
    virtual WalletFfiError sync_to_block(uint64_t block_id) = 0;
    virtual WalletFfiError get_last_synced_block(uint64_t* output_block_id) = 0;
    virtual WalletFfiError get_current_block_height(uint64_t* output_block_height) = 0;

    // Operations
    virtual WalletFfiError transfer_public(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError transfer_shielded(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError transfer_deshielded(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError transfer_private(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError transfer_shielded_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError transfer_private_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError register_public_account(
        const QString& account_id_hex,
        QString& output_result_json
    ) = 0;
    virtual WalletFfiError register_private_account(
        const QString& account_id_hex,
        QString& output_result_json
    ) = 0;

    // Wallet Lifecycle
    virtual WalletFfiError create_new(
        const QString& config_path,
        const QString& storage_path,
        const QString& password
    ) = 0;
    virtual WalletFfiError open(const QString& config_path, const QString& storage_path) = 0;
    virtual WalletFfiError save() = 0;

    // Configuration & Metadata
    virtual QString get_sequencer_addr() = 0;
};

#define ILogosExecutionZoneWalletModule_iid "org.logos.ilogosexecutionzonewalletmodule"
Q_DECLARE_INTERFACE(ILogosExecutionZoneWalletModule, ILogosExecutionZoneWalletModule_iid)

#endif
