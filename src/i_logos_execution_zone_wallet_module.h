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
    virtual QString create_account_public() = 0;
    virtual QString create_account_private() = 0;
    virtual QJsonArray list_accounts() = 0;

    // Account Queries
    virtual QString get_balance(const QString& account_id_hex, bool is_public) = 0;
    virtual QString get_account_public(const QString& account_id_hex) = 0;
    virtual QString get_account_private(const QString& account_id_hex) = 0;
    virtual QString get_public_account_key(const QString& account_id_hex) = 0;
    virtual QString get_private_account_keys(const QString& account_id_hex) = 0;

    // Account Encoding
    virtual QString account_id_to_base58(const QString& account_id_hex) = 0;
    virtual QString account_id_from_base58(const QString& base58_str) = 0;

    // Blockchain Synchronisation
    virtual WalletFfiError sync_to_block(uint64_t block_id) = 0;
    virtual uint64_t get_last_synced_block() = 0;
    virtual uint64_t get_current_block_height() = 0;

    // Pinata
    virtual QString claim_pinata(
        const QString& pinata_account_id_hex,
        const QString& winner_account_id_hex,
        const QString& solution_le16_hex
    ) = 0;
    virtual QString claim_pinata_private_owned_already_initialized(
        const QString& pinata_account_id_hex,
        const QString& winner_account_id_hex,
        const QString& solution_le16_hex,
        uint64_t winner_proof_index,
        const QString& winner_proof_siblings_json
    ) = 0;
    virtual QString claim_pinata_private_owned_not_initialized(
        const QString& pinata_account_id_hex,
        const QString& winner_account_id_hex,
        const QString& solution_le16_hex
    ) = 0;

    // Operations
    virtual QString transfer_public(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString transfer_shielded(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString transfer_deshielded(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString transfer_private(
        const QString& from_hex,
        const QString& to_keys_json,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString transfer_shielded_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString transfer_private_owned(
        const QString& from_hex,
        const QString& to_hex,
        const QString& amount_le16_hex
    ) = 0;
    virtual QString register_public_account(const QString& account_id_hex) = 0;
    virtual QString register_private_account(const QString& account_id_hex) = 0;

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
