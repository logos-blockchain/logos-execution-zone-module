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
    virtual WalletFfiError create_account_public(FfiBytes32* out_account_id) = 0;
    virtual WalletFfiError create_account_private(FfiBytes32* out_account_id) = 0;
    virtual WalletFfiError list_accounts(FfiAccountList* out_list) = 0;

    // Account Queries
    virtual WalletFfiError get_balance(
        const FfiBytes32* account_id,
        bool is_public,
        QByteArray* out_balance_le16
    ) = 0;
    virtual WalletFfiError get_account_public(
        const FfiBytes32* account_id,
        FfiAccount* out_account
    ) = 0;
    virtual WalletFfiError get_account_private(
        const FfiBytes32* account_id,
        FfiAccount* out_account
    ) = 0;
    virtual WalletFfiError get_public_account_key(
        const FfiBytes32* account_id,
        FfiPublicAccountKey* out_public_key
    ) = 0;
    virtual WalletFfiError get_private_account_keys(
        const FfiBytes32* account_id,
        FfiPrivateAccountKeys* out_keys
    ) = 0;

    // Account Encoding
    virtual QString account_id_to_base58(const FfiBytes32* account_id) = 0;
    virtual WalletFfiError account_id_from_base58(const QString& base58_str, FfiBytes32* out_account_id) = 0;

    // Blockchain Synchronisation
    virtual WalletFfiError sync_to_block(uint64_t block_id) = 0;
    virtual WalletFfiError get_last_synced_block(uint64_t* out_block_id) = 0;
    virtual WalletFfiError get_current_block_height(uint64_t* out_block_height) = 0;

    // Operations
    virtual WalletFfiError transfer_public(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError transfer_shielded(
        const FfiBytes32* from,
        const FfiPrivateAccountKeys* to_keys,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError transfer_deshielded(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError transfer_private(
        const FfiBytes32* from,
        const FfiPrivateAccountKeys* to_keys,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError transfer_shielded_owned(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError transfer_private_owned(
        const FfiBytes32* from,
        const FfiBytes32* to,
        const QByteArray& amount_le16,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError register_public_account(
        const FfiBytes32* account_id,
        FfiTransferResult* out_result
    ) = 0;
    virtual WalletFfiError register_private_account(
        const FfiBytes32* account_id,
        FfiTransferResult* out_result
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
