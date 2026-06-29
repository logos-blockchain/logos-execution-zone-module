#ifndef LOGOS_EXECUTION_ZONE_WALLET_MODULE_H
#define LOGOS_EXECUTION_ZONE_WALLET_MODULE_H

#include <cstdint>
#include <string>

#include <logos_json.h>

extern "C" {
#include <wallet_ffi.h>
}

// Universal (Qt-free) execution-zone wallet module. The Qt glue (provider
// object + plugin) is generated from this header by logos-cpp-generator, which
// maps the std return types below to the Qt signatures callers invoke:
//   std::string -> QString, int64_t -> int, LogosList -> QVariantList.
//
// NOTE: the generator parses this header line-by-line and only recognises a
// method when its declaration ends with ';' on a single line. Keep every
// method declaration on ONE line — multi-line signatures are silently dropped.
class LogosExecutionZoneWalletModule {
public:
    LogosExecutionZoneWalletModule();
    ~LogosExecutionZoneWalletModule();

    LogosExecutionZoneWalletModule(const LogosExecutionZoneWalletModule&) = delete;
    LogosExecutionZoneWalletModule& operator=(const LogosExecutionZoneWalletModule&) = delete;

    std::string name() const;
    std::string version() const;

    // === Wallet Lifecycle ===
    std::string create_new(const std::string& config_path, const std::string& storage_path, const std::string& password);
    int64_t open(const std::string& config_path, const std::string& storage_path);
    int64_t save();

    int64_t restore_storage(const std::string& mnemonic, const std::string password, uint32_t depth);

    // === Account Management ===
    std::string create_account_public();
    std::string create_account_private();
    LogosList list_accounts();

    // === Account Queries ===
    std::string get_balance(const std::string& account_id_hex, bool is_public);
    std::string get_account_public(const std::string& account_id_hex);
    std::string get_account_private(const std::string& account_id_hex);
    std::string get_public_account_key(const std::string& account_id_hex);
    std::string get_private_account_keys(const std::string& account_id_hex);

    // === Account Encoding ===
    std::string account_id_to_base58(const std::string& account_id_hex);
    std::string account_id_from_base58(const std::string& base58_str);

    // === Blockchain Synchronisation ===
    int64_t sync_to_block(int64_t block_id);
    int64_t get_last_synced_block();
    int64_t get_current_block_height();

    // === Pinata claiming ===
    std::string claim_pinata(const std::string& pinata_account_id_hex, const std::string& winner_account_id_hex, const std::string& solution_le16_hex);
    std::string claim_pinata_private_owned_already_initialized(const std::string& pinata_account_id_hex, const std::string& winner_account_id_hex, const std::string& solution_le16_hex, int64_t winner_proof_index, const std::string& winner_proof_siblings_json);
    std::string claim_pinata_private_owned_not_initialized(const std::string& pinata_account_id_hex, const std::string& winner_account_id_hex, const std::string& solution_le16_hex);

    // === Operations ===
    std::string transfer_public(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_shielded(const std::string& from_hex, const std::string& to_keys_json, const std::string& amount_le16_hex);
    std::string transfer_deshielded(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_private(const std::string& from_hex, const std::string& to_keys_json, const std::string& amount_le16_hex);
    std::string transfer_shielded_owned(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_private_owned(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string register_public_account(const std::string& account_id_hex);
    std::string register_private_account(const std::string& account_id_hex);

    std::vector<uint8_t> authenticated_transfer_elf();
    std::vector<uint8_t> token_elf();
    std::vector<uint8_t> amm_elf();
    std::vector<uint8_t> ata_elf();

    std::string send_generic_public_transaction(const std::vector<std::string>& account_ids, const std::vector<bool>& signing_requirements, const std::vector<uint32_t>& instruction, const std::string& program_id_hex);
    std::string send_generic_private_transaction(
        const std::vector<std::string>& account_ids,
        const std::vector<uint32_t>& instruction,
        const std::vector<uint8_t>& program_elf,
        const std::vector<std::vector<uint8_t>>& program_dependencies
    );
    std::string send_program_deployment_transaction(
        const std::vector<uint8_t>& program_elf
    );

    // === Bridge (L1 Bedrock <-> L2) ===
    std::string bridge_withdraw(const std::string& from_hex, const std::string& bedrock_account_pk_hex, uint64_t amount);

    // === Vault claiming (L1 deposits credited to an owner's vault account) ===
    std::string get_vault_balance(const std::string& owner_account_id_hex);
    std::string vault_claim(const std::string& owner_account_id_hex, const std::string& amount_le16_hex);
    std::string vault_claim_private(const std::string& owner_account_id_hex, const std::string& amount_le16_hex);

    // === Configuration ===
    std::string get_sequencer_addr();

private:
    WalletHandle* walletHandle = nullptr;
};

#endif // LOGOS_EXECUTION_ZONE_WALLET_MODULE_H
