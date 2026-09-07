#ifndef LEZ_CORE_MODULE_H
#define LEZ_CORE_MODULE_H

#include <cstdint>
#include <string>

#include <logos_json.h>
#include <logos_module_context.h>

extern "C" {
#include <wallet_ffi.h>
}

constexpr const char* LEZ_NO_WALLET_DIR = "-";

// Universal (Qt-free) execution-zone core module. The Qt glue (provider
// object + plugin) is generated from this header by logos-cpp-generator, which
// maps the std return types below to the Qt signatures callers invoke:
//   std::string -> QString, int64_t -> int, LogosList -> QVariantList.
//
// NOTE: the generator parses this header line-by-line and only recognises a
// method when its declaration ends with ';' on a single line. Keep every
// method declaration on ONE line — multi-line signatures are silently dropped.
// 
// This seems to be fixed upstream in logos-cpp-sdk #91; 
// (tracked in https://github.com/logos-co/logos-cpp-sdk/issues/59)
// but our current pinned SDK does not include it; so instead we keep everything
// single-line and disable formatting for this region
//
// clang-format off
class LEZCoreModule : public LogosModuleContext {
public:
    LEZCoreModule();
    ~LEZCoreModule();

    LEZCoreModule(const LEZCoreModule&) = delete;
    LEZCoreModule& operator=(const LEZCoreModule&) = delete;

    std::string name() const;
    std::string version() const;
    std::string wallet_dir();

    std::string create_new(const std::string& config_path, const std::string& storage_path, const std::string& statistics_path, const std::string& password);
    int64_t open(const std::string& config_path, const std::string& storage_path, const std::string& statistics_path);
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

    // === Operations ===
    // A fresh public account is claimed by its first funded transfer (`to` owned by
    // this wallet); there is no separate registration under fees.
    std::string transfer_public(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_shielded(const std::string& from_hex, const std::string& to_keys_json, const std::string& amount_le16_hex);
    std::string transfer_deshielded(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_private(const std::string& from_hex, const std::string& to_keys_json, const std::string& amount_le16_hex);
    std::string transfer_shielded_owned(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);
    std::string transfer_private_owned(const std::string& from_hex, const std::string& to_hex, const std::string& amount_le16_hex);

    std::vector<uint8_t> authenticated_transfer_elf();
    std::vector<uint8_t> token_elf();
    std::vector<uint8_t> amm_elf();
    std::vector<uint8_t> ata_elf();

    // `instruction` uses a byte-string (`bstr`) IPC type so the auto-generated
    // Qt/QtRO glue can serialize it across the module process boundary. Declaring
    // it as std::vector<uint32_t> makes the header->LIDL generator fall back to an
    // opaque `any` with no QDataStream operators, silently dropping every argument
    // over QtRO. The bytes are the Borsh-serialized instruction, passed to the
    // FFI untouched (`lee` expects preserialized instruction data).
    std::string send_generic_public_transaction(const std::vector<std::string>& account_ids, const std::vector<bool>& signing_requirements, const std::vector<uint8_t>& instruction, const std::string& program_id_hex);
    std::string send_generic_private_transaction(const std::vector<std::string>& account_ids, const std::vector<uint8_t>& instruction, const std::vector<uint8_t>& program_elf, const std::vector<std::vector<uint8_t>>& program_dependencies);
    // Deploys `program_elf` via `program_loader`: one write-once segment account per
    // 96 KiB chunk of the ELF (in chain order), plus a header account pointing at the
    // chain. The wallet must hold the signing keys for every account passed in.
    std::string send_program_deployment_transaction(const std::string& header_account_id_hex, const std::vector<std::string>& segment_account_ids_hex, const std::vector<uint8_t>& program_elf, bool immutable);

    bool poll_transaction_status(const std::string& tx_hash_hex);

    // === Bridge (L1 Bedrock <-> L2) ===
    std::string bridge_withdraw(const std::string& from_hex, const std::string& bedrock_account_pk_hex, uint64_t amount);

    // === Configuration ===
    std::string get_sequencer_addr();

    // === Labels ===
    bool check_label_available(const std::string& label);
    int64_t add_label(const std::string& label, const std::string& account_id_hex, bool is_private);
    std::string resolve_label(const std::string& label);
    std::vector<std::string> get_all_labels_for_account(const std::string& account_id_hex, bool is_private);

private:
    WalletHandle* walletHandle = nullptr;
};
// clang-format on

#endif // LEZ_CORE_MODULE_H
