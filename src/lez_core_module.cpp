#include "lez_core_module.h"
#include "lez_core_ffi_marshalling.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <vector>

#include <nlohmann/json.hpp>

using namespace marshalling;

namespace {
    // Mentions borrow the identities' heap fields; free the identities only after use.
    bool buildAccountMentions(
        const std::vector<FfiAccountIdentity>& identities,
        const std::vector<std::string>& actor_state_program_account_ids_hex,
        std::vector<FfiAccountMention>& out_mentions,
        std::string& out_error
    ) {
        if (!actor_state_program_account_ids_hex.empty() && actor_state_program_account_ids_hex.size() != identities.size()) {
            out_error = "actor_state_program_account_ids_hex must be empty or match account_ids in size";
            return false;
        }

        out_mentions.clear();
        out_mentions.reserve(identities.size());
        for (size_t i = 0; i < identities.size(); ++i) {
            FfiAccountMention mention{};
            mention.identity = identities[i];

            const bool hasOverride =
                !actor_state_program_account_ids_hex.empty() && !actor_state_program_account_ids_hex[i].empty();
            if (hasOverride) {
                if (!hexToBytes32(actor_state_program_account_ids_hex[i], &mention.program_account_id)) {
                    out_error = "invalid actor_state_program_account_ids_hex[" + std::to_string(i) + "]";
                    return false;
                }
            } else {
                out_error =
                    "actor_state_program_account_ids_hex[" + std::to_string(i) +
                    "] is required when the root program's account id is unknown (shadow root without account_id)";
                return false;
            }
            out_mentions.push_back(mention);
        }
        return true;
    }

    // Identities for one private send. Those resolved by the wallet FFI hold Rust allocations
    // and go back through `wallet_ffi_free_account_identity`; foreign ones point at viewing keys
    // held here instead, so they must never reach it.
    struct PrivateSendAccounts {
        std::vector<FfiAccountIdentity> identities;
        std::vector<bool> resolved_by_ffi;
        std::vector<std::unique_ptr<std::vector<uint8_t>>> viewing_keys;

        PrivateSendAccounts() = default;
        PrivateSendAccounts(const PrivateSendAccounts&) = delete;
        PrivateSendAccounts& operator=(const PrivateSendAccounts&) = delete;

        ~PrivateSendAccounts() {
            for (size_t i = 0; i < identities.size(); ++i) {
                if (resolved_by_ffi[i])
                    wallet_ffi_free_account_identity(&identities[i]);
            }
        }

        void addResolved(const FfiAccountIdentity& identity) {
            identities.push_back(identity);
            resolved_by_ffi.push_back(true);
        }

        void addForeign(FfiAccountIdentity identity, std::vector<uint8_t> viewing_key) {
            viewing_keys.push_back(std::make_unique<std::vector<uint8_t>>(std::move(viewing_key)));
            identity.viewing_public_key = viewing_keys.back()->data();
            identity.viewing_public_key_len = static_cast<uintptr_t>(viewing_keys.back()->size());
            identities.push_back(identity);
            resolved_by_ffi.push_back(false);
        }
    };

    bool resolveOwnedPrivateAccounts(
        WalletHandle* wallet_handle,
        const std::vector<std::string>& account_ids,
        PrivateSendAccounts& accounts,
        std::string& error
    ) {
        for (size_t i = 0; i < account_ids.size(); ++i) {
            FfiBytes32 id{};
            if (!hexToBytes32(account_ids[i], &id)) {
                error = "invalid account_id_hex[" + std::to_string(i) + "]";
                return false;
            }
            FfiAccountIdentity identity{};
            const FfiOperationError ffi_error = wallet_ffi_resolve_private_account(wallet_handle, id, &identity);
            if (ffi_error != FfiOperationError_Success) {
                error = "wallet_ffi_resolve_private_account failed for account " + std::to_string(i) +
                        ": wallet FFI error " + std::to_string(ffi_error);
                return false;
            }
            accounts.addResolved(identity);
        }
        return true;
    }

    // ML-KEM-768 encapsulation key length; the wallet FFI rejects any other.
    constexpr size_t VIEWING_PUBLIC_KEY_LEN = 1184;

    // One `accounts_json` entry of `send_generic_private_transaction_with_accounts`.
    bool resolveDescribedAccount(
        WalletHandle* wallet_handle,
        const std::string& json,
        PrivateSendAccounts& accounts,
        std::string& error
    ) {
        const nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object() || !doc.contains(JsonKeys::Kind) ||
            !doc[JsonKeys::Kind].is_string()) {
            error = "needs a \"kind\"";
            return false;
        }
        const std::string kind = doc[JsonKeys::Kind].get<std::string>();

        if (kind == JsonKeys::KindPrivateForeign) {
            FfiAccountIdentity identity{};
            identity.kind = FfiAccountIdentityKind::FfiAccountIdentityKind_PrivateForeign;
            if (!doc.contains(JsonKeys::NullifierPublicKey) || !doc[JsonKeys::NullifierPublicKey].is_string() ||
                !hexToBytes32(doc[JsonKeys::NullifierPublicKey].get<std::string>(), &identity.nullifier_public_key)) {
                error = "private_foreign needs a 32-byte \"nullifier_public_key\"";
                return false;
            }
            std::vector<uint8_t> viewing_key;
            if (!doc.contains(JsonKeys::ViewingPublicKey) || !doc[JsonKeys::ViewingPublicKey].is_string() ||
                !hexToBytes(
                    doc[JsonKeys::ViewingPublicKey].get<std::string>(),
                    viewing_key,
                    static_cast<int>(VIEWING_PUBLIC_KEY_LEN)
                )) {
                error = "private_foreign needs a 1184-byte \"viewing_public_key\"";
                return false;
            }
            accounts.addForeign(identity, std::move(viewing_key));
            return true;
        }

        FfiBytes32 id{};
        if (!doc.contains(JsonKeys::AccountId) || !doc[JsonKeys::AccountId].is_string() ||
            !hexToBytes32(doc[JsonKeys::AccountId].get<std::string>(), &id)) {
            error = kind + " needs a 32-byte \"account_id\"";
            return false;
        }
        FfiAccountIdentity identity{};
        FfiOperationError ffi_error = FfiOperationError_Success;
        if (kind == JsonKeys::KindPrivateOwned) {
            ffi_error = wallet_ffi_resolve_private_account(wallet_handle, id, &identity);
        } else if (kind == JsonKeys::KindPublic || kind == JsonKeys::KindPublicNoSign) {
            ffi_error = wallet_ffi_resolve_public_account(id, kind == JsonKeys::KindPublic, &identity);
        } else {
            error = "unknown kind \"" + kind + "\"";
            return false;
        }
        if (ffi_error != FfiOperationError_Success) {
            error = "resolving " + kind + " failed: wallet FFI error " + std::to_string(ffi_error);
            return false;
        }
        accounts.addResolved(identity);
        return true;
    }

    // Shared by both generic private sends, which differ only in how they resolve their accounts.
    std::string sendGenericPrivateTransaction(
        WalletHandle* wallet_handle,
        const char* method,
        const std::vector<FfiAccountIdentity>& identities,
        const uint64_t root_mention,
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& program_elf,
        const std::string& program_kind_json,
        const std::vector<std::vector<uint8_t>>& program_dependencies,
        const std::vector<std::string>& dependency_kinds_json,
        const std::vector<std::string>& actor_state_program_account_ids_hex
    ) {
        if (dependency_kinds_json.size() != program_dependencies.size()) {
            fprintf(stderr, "%s: dependency_kinds_json size must match program_dependencies\n", method);
            return transferResultToJson(
                nullptr, std::string(method) + ": dependency_kinds_json size must match program_dependencies"
            );
        }

        ParsedProgramKind root{};
        if (!jsonToProgramKind(program_kind_json, &root)) {
            fprintf(stderr, "%s: invalid program_kind_json\n", method);
            return transferResultToJson(nullptr, std::string(method) + ": invalid program_kind_json");
        }
        // Native execution supplies no bytecode, so it can only be dispatched at a known address.
        if (program_elf.empty() && root.kind != FfiProgramKind::FfiProgramKind_ProgramDisclosed) {
            fprintf(stderr, "%s: an empty program_elf requires a disclosed kind\n", method);
            return transferResultToJson(
                nullptr, std::string(method) + ": an empty program_elf requires a disclosed kind"
            );
        }

        // The FFI picks the root as the entry whose account_id equals self_account_id, so shadow
        // dependencies (whose account_id is otherwise ignored) get one that never matches.
        const FfiBytes32 self_account_id = root.account_id;
        FfiBytes32 never_self{};
        for (int i = 0; i < 32; ++i)
            never_self.data[i] = static_cast<uint8_t>(~self_account_id.data[i]);

        std::vector<ParsedProgramKind> dependency_kinds(program_dependencies.size());
        for (size_t i = 0; i < program_dependencies.size(); ++i) {
            if (!jsonToProgramKind(dependency_kinds_json[i], &dependency_kinds[i])) {
                fprintf(stderr, "%s: invalid dependency_kinds_json[%zu]\n", method, i);
                return transferResultToJson(
                    nullptr, std::string(method) + ": invalid dependency_kinds_json[" + std::to_string(i) + "]"
                );
            }
            if (dependency_kinds[i].kind != FfiProgramKind::FfiProgramKind_ProgramShadow &&
                memcmp(dependency_kinds[i].account_id.data, self_account_id.data, 32) == 0) {
                fprintf(stderr, "%s: dependency %zu has the root's account_id\n", method, i);
                return transferResultToJson(
                    nullptr, std::string(method) + ": dependency " + std::to_string(i) + " has the root's account_id"
                );
            }
        }

        auto toFfiDependency =
            [](const std::vector<uint8_t>& elf, const ParsedProgramKind& parsed, const FfiBytes32& account_id) {
                FfiDependency dependency{};
                dependency.program.elf_data = elf.data();
                dependency.program.elf_size = static_cast<uintptr_t>(elf.size());
                dependency.account_id = account_id;
                dependency.kind = parsed.kind;
                dependency.program_header = parsed.program_header;
                dependency.membership_proof = parsed.membership_proof;
                return dependency;
            };

        std::vector<FfiDependency> programs;
        programs.reserve(program_dependencies.size() + 1);
        if (!program_elf.empty())
            programs.push_back(toFfiDependency(program_elf, root, self_account_id));
        for (size_t i = 0; i < program_dependencies.size(); ++i) {
            const ParsedProgramKind& parsed = dependency_kinds[i];
            const bool is_shadow = parsed.kind == FfiProgramKind::FfiProgramKind_ProgramShadow;
            programs.push_back(
                toFfiDependency(program_dependencies[i], parsed, is_shadow ? never_self : parsed.account_id)
            );
        }

        FfiProgramCatalog program_with_dependencies{};
        program_with_dependencies.programs = programs.data();
        program_with_dependencies.programs_size = static_cast<uintptr_t>(programs.size());

        std::vector<FfiAccountMention> mentions;
        std::string mentions_error;
        if (!buildAccountMentions(
                identities,
                actor_state_program_account_ids_hex,
                mentions,
                mentions_error
            )) {
            fprintf(stderr, "%s: %s\n", method, mentions_error.c_str());
            return transferResultToJson(nullptr, std::string(method) + ": " + mentions_error);
        }

        FfiTransactionResult result{};

        const FfiOperationError error = wallet_ffi_send_generic_private_transaction(
            wallet_handle,
            mentions.data(),
            static_cast<uintptr_t>(mentions.size()),
            static_cast<uintptr_t>(root_mention),
            message.data(),
            static_cast<uintptr_t>(message.size()),
            &program_with_dependencies,
            &result
        );

        if (error != FfiOperationError_Success) {
            fprintf(stderr, "%s: wallet FFI error %d\n", method, error);
            return transferResultToJson(nullptr, std::string(method) + ": wallet FFI error " + std::to_string(error));
        }
        std::string resultJson = genericTransactionResultToJson(&result, std::string());
        wallet_ffi_free_transaction_result(&result);
        return resultJson;
    }

} // namespace

LEZCoreModule::LEZCoreModule() = default;

LEZCoreModule::~LEZCoreModule() {
    if (walletHandle) {
        wallet_ffi_destroy(walletHandle);
        walletHandle = nullptr;
    }
}

std::string LEZCoreModule::name() const {
    return "lez_core";
}

std::string LEZCoreModule::version() const {
    return "0.6.0";
}

// === Persistent locations ===

std::string LEZCoreModule::wallet_dir() {
    if (!isContextReady() || instancePersistencePath().empty())
        return LEZ_NO_WALLET_DIR;
    return instancePersistencePath();

    namespace fs = std::filesystem;
    const fs::path dir = fs::path(instancePersistencePath()) / "wallet";

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec)
        return LEZ_NO_WALLET_DIR;

    return dir.string();
}

std::string LEZCoreModule::sequencer_dir() {
    if (!isContextReady() || instancePersistencePath().empty())
        return LEZ_NO_WALLET_DIR;
    return instancePersistencePath();

    namespace fs = std::filesystem;
    const fs::path dir = fs::path(instancePersistencePath()) / "sequencer";

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec)
        return LEZ_NO_WALLET_DIR;

    return dir.string();
}

// === Account Management ===

std::string LEZCoreModule::create_account_public() {
    FfiBytes32 id{};
    const FfiOperationError error = wallet_ffi_create_account_public(walletHandle, &id);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "create_account_public: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

std::string LEZCoreModule::create_account_private() {
    FfiBytes32 id{};
    const FfiOperationError error = wallet_ffi_create_account_private(walletHandle, &id);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "create_account_private: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

LogosList LEZCoreModule::list_accounts() {
    LogosList result = nlohmann::json::array();
    FfiAccountList list{};
    const FfiOperationError error = wallet_ffi_list_accounts(walletHandle, &list);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "list_accounts: wallet FFI error %d\n", error);
        return result;
    }
    for (uintptr_t i = 0; i < list.count; ++i) {
        result.push_back(ffiAccountListEntryToJson(list.entries[i]));
    }
    wallet_ffi_free_account_list(&list);
    return result;
}

// === Account Queries ===

std::string LEZCoreModule::get_balance(const std::string& account_id_hex, const bool is_public) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_balance: invalid account_id_hex\n");
        return {};
    }

    uint8_t balance[16] = {0};
    const FfiOperationError error = wallet_ffi_get_balance(walletHandle, &id, is_public, &balance);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_balance: wallet FFI error %d\n", error);
        return {};
    }
    // Return decimal string for UI display (balance is 16-byte little-endian u128).
    return balanceLe16ToDecimalString(balance);
}

std::string LEZCoreModule::get_account_public(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_account_public: invalid account_id_hex\n");
        return {};
    }
    FfiAccount account{};
    const FfiOperationError error = wallet_ffi_get_account_public(walletHandle, &id, &account);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_account_public: wallet FFI error %d\n", error);
        return {};
    }
    std::string result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

std::string LEZCoreModule::get_account_private(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_account_private: invalid account_id_hex\n");
        return {};
    }
    FfiAccount account{};
    const FfiOperationError error = wallet_ffi_get_account_private(walletHandle, &id, &account);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_account_private: wallet FFI error %d\n", error);
        return {};
    }
    std::string result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

std::string LEZCoreModule::get_public_account_key(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_public_account_key: invalid account_id_hex\n");
        return {};
    }
    FfiPublicAccountKey key{};
    const FfiOperationError error = wallet_ffi_get_public_account_key(walletHandle, &id, &key);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_public_account_key: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(key.public_key);
}

std::string LEZCoreModule::get_private_account_keys(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_private_account_keys: invalid account_id_hex\n");
        return {};
    }
    FfiPrivateAccountKeys keys{};
    const FfiOperationError error = wallet_ffi_get_private_account_keys(walletHandle, &id, &keys);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_private_account_keys: wallet FFI error %d\n", error);
        return {};
    }

    std::string result = ffiPrivateAccountKeysToJson(keys);
    primitives_ffi_free_private_account_keys(&keys);
    return result;
}

// === Account Encoding ===

std::string LEZCoreModule::account_id_to_base58(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "account_id_to_base58: invalid account_id_hex\n");
        return {};
    }

    char* str = wallet_ffi_account_id_to_base58(&id);
    if (!str) {
        fprintf(stderr, "account_id_to_base58: wallet_ffi returned null\n");
        return {};
    }

    std::string value(str);
    primitives_ffi_free_cstring(str);
    return value;
}

std::string LEZCoreModule::account_id_from_base58(const std::string& base58_str) {
    FfiBytes32 id{};
    const FfiOperationError error = wallet_ffi_account_id_from_base58(base58_str.c_str(), &id);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "account_id_from_base58: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

// === Blockchain Synchronisation ===

int64_t LEZCoreModule::sync_to_block(const int64_t block_id) {
    return wallet_ffi_sync_to_block(walletHandle, static_cast<uint64_t>(block_id));
}

int64_t LEZCoreModule::get_last_synced_block() {
    uint64_t block_id = 0;
    const FfiOperationError error = wallet_ffi_get_last_synced_block(walletHandle, &block_id);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_last_synced_block: wallet FFI error %d\n", error);
        return 0;
    }
    return static_cast<int64_t>(block_id);
}

int64_t LEZCoreModule::get_current_block_height() {
    uint64_t block_height = 0;
    const FfiOperationError error = wallet_ffi_get_current_block_height(walletHandle, &block_height);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "get_current_block_height: wallet FFI error %d\n", error);
        return 0;
    }
    return static_cast<int64_t>(block_height);
}

// === Operations ===

std::string LEZCoreModule::transfer_public(
    const std::string& from_hex,
    const std::string& to_hex,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        fprintf(stderr, "transfer_public: invalid account id hex\n");
        return transferResultToJson(nullptr, "transfer_public: invalid account id hex");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_public: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        return transferResultToJson(nullptr, "transfer_public: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    FfiTransferResult result{};
    const FfiOperationError error = wallet_ffi_transfer_public(walletHandle, &fromId, &toId, &amount, &result);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_public: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_public: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::transfer_shielded(
    const std::string& from_hex,
    const std::string& to_keys_json,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        fprintf(stderr, "transfer_shielded: invalid from account id hex\n");
        return transferResultToJson(nullptr, "transfer_shielded: invalid from account id hex");
    }

    FfiPrivateAccountKeys toKeys{};
    if (!jsonToFfiPrivateAccountKeys(to_keys_json, &toKeys)) {
        fprintf(stderr, "transfer_shielded: failed to parse to_keys_json\n");
        return transferResultToJson(nullptr, "transfer_shielded: failed to parse to_keys_json");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        primitives_ffi_free_private_account_keys(&toKeys);
        return transferResultToJson(nullptr, "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // TODO: Add keycard support
    const char* key_path = nullptr;

    FfiTransferResult result{};
    const FfiOperationError error =
        wallet_ffi_transfer_shielded(walletHandle, &fromId, &toKeys, &amount, key_path, &result);
    primitives_ffi_free_private_account_keys(&toKeys);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_shielded: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_shielded: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::transfer_deshielded(
    const std::string& from_hex,
    const std::string& to_hex,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        fprintf(stderr, "transfer_deshielded: invalid account id hex\n");
        return transferResultToJson(nullptr, "transfer_deshielded: invalid account id hex");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_deshielded: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        return transferResultToJson(
            nullptr, "transfer_deshielded: amount_le16_hex must be 32 hex characters (16 bytes)"
        );
    }

    FfiTransferResult result{};
    const FfiOperationError error = wallet_ffi_transfer_deshielded(walletHandle, &fromId, &toId, &amount, &result);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_deshielded: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_deshielded: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::transfer_private(
    const std::string& from_hex,
    const std::string& to_keys_json,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        fprintf(stderr, "transfer_private: invalid from account id hex\n");
        return transferResultToJson(nullptr, "transfer_private: invalid from account id hex");
    }

    FfiPrivateAccountKeys toKeys{};
    if (!jsonToFfiPrivateAccountKeys(to_keys_json, &toKeys)) {
        fprintf(stderr, "transfer_private: failed to parse to_keys_json\n");
        return transferResultToJson(nullptr, "transfer_private: failed to parse to_keys_json");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        primitives_ffi_free_private_account_keys(&toKeys);
        return transferResultToJson(nullptr, "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    FfiTransferResult result{};
    const FfiOperationError error =
        wallet_ffi_transfer_private(walletHandle, &fromId, &toKeys, &amount, &result);
    primitives_ffi_free_private_account_keys(&toKeys);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_private: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_private: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::transfer_shielded_owned(
    const std::string& from_hex,
    const std::string& to_hex,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        fprintf(stderr, "transfer_shielded_owned: invalid account id hex\n");
        return transferResultToJson(nullptr, "transfer_shielded_owned: invalid account id hex");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_shielded_owned: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        return transferResultToJson(
            nullptr, "transfer_shielded_owned: amount_le16_hex must be 32 hex characters (16 bytes)"
        );
    }

    // ToDo: Add keycard support
    const char* key_path = nullptr;

    FfiTransferResult result{};
    const FfiOperationError error =
        wallet_ffi_transfer_shielded_owned(walletHandle, &fromId, &toId, &amount, key_path, &result);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_shielded_owned: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_shielded_owned: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::transfer_private_owned(
    const std::string& from_hex,
    const std::string& to_hex,
    const std::string& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        fprintf(stderr, "transfer_private_owned: invalid account id hex\n");
        return transferResultToJson(nullptr, "transfer_private_owned: invalid account id hex");
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        fprintf(stderr, "transfer_private_owned: amount_le16_hex must be 32 hex characters (16 bytes)\n");
        return transferResultToJson(
            nullptr, "transfer_private_owned: amount_le16_hex must be 32 hex characters (16 bytes)"
        );
    }

    FfiTransferResult result{};
    const FfiOperationError error = wallet_ffi_transfer_private_owned(walletHandle, &fromId, &toId, &amount, &result);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "transfer_private_owned: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_private_owned: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

// === Bridge (L1 Bedrock <-> L2) ===

std::string LEZCoreModule::bridge_withdraw(
    const std::string& from_hex,
    const std::string& bedrock_account_pk_hex,
    const uint64_t amount
) {
    FfiBytes32 fromId{}, bedrockAccountPk{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(bedrock_account_pk_hex, &bedrockAccountPk)) {
        fprintf(stderr, "bridge_withdraw: invalid account id or bedrock account pk hex\n");
        return transferResultToJson(nullptr, "bridge_withdraw: invalid account id or bedrock account pk hex");
    }

    FfiTransferResult result{};
    const FfiOperationError error = wallet_ffi_bridge_withdraw(walletHandle, &fromId, amount, &bedrockAccountPk, &result);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "bridge_withdraw: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "bridge_withdraw: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LEZCoreModule::send_generic_public_transaction(
    const std::vector<std::string>& account_ids,
    const uint64_t root_mention,
    const std::vector<bool>& signing_requirements,
    const std::vector<uint8_t>& message,
    const std::string& payer_account_id_hex,
    const std::vector<std::string>& actor_state_program_account_ids_hex
) {
    if (signing_requirements.size() != account_ids.size()) {
        fprintf(stderr, "send_generic_public_transaction: signing_requirements size must match account_ids\n");
        return transferResultToJson(
            nullptr, "send_generic_public_transaction: signing_requirements size must match account_ids"
        );
    }

    FfiBytes32 payer{};
    const FfiBytes32* payer_ptr = nullptr;
    if (!payer_account_id_hex.empty()) {
        if (!hexToBytes32(payer_account_id_hex, &payer)) {
            fprintf(stderr, "send_generic_public_transaction: invalid payer_account_id_hex\n");
            return transferResultToJson(nullptr, "send_generic_public_transaction: invalid payer_account_id_hex");
        }
        payer_ptr = &payer;
    }

    std::vector<FfiAccountIdentity> identities_resolved;
    identities_resolved.reserve(account_ids.size());
    auto free_identities = [&identities_resolved]() {
        for (FfiAccountIdentity& acc_identity : identities_resolved) {
            wallet_ffi_free_account_identity(&acc_identity);
        }
    };

    for (int i = 0; i < account_ids.size(); ++i) {
        FfiAccountIdentity acc_identity{};

        FfiBytes32 id{};
        if (!hexToBytes32(account_ids[i], &id)) {
            fprintf(stderr, "wallet_ffi_resolve_public_account: invalid account_id_hex");
            free_identities();
            return transferResultToJson(
                nullptr, std::string("wallet_ffi_resolve_public_account: invalid account_id_hex")
            );
        }

        FfiOperationError error = wallet_ffi_resolve_public_account(id, signing_requirements[i], &acc_identity);
        if (error != FfiOperationError_Success) {
            fprintf(stderr, "wallet_ffi_resolve_public_account failed for index %d: wallet FFI error %d\n", i, error);
            free_identities();
            return transferResultToJson(
                nullptr, std::string("wallet_ffi_resolve_public_account: wallet FFI error ") + std::to_string(error)
            );
        }
        identities_resolved.push_back(acc_identity);
    }

    std::vector<FfiAccountMention> mentions;
    std::string mentions_error;
    if (!buildAccountMentions(
            identities_resolved, actor_state_program_account_ids_hex, mentions, mentions_error
        )) {
        fprintf(stderr, "send_generic_public_transaction: %s\n", mentions_error.c_str());
        free_identities();
        return transferResultToJson(nullptr, "send_generic_public_transaction: " + mentions_error);
    }

    FfiTransactionResult result{};

    const FfiOperationError error = wallet_ffi_send_generic_public_transaction(
        walletHandle,
        mentions.data(),
        static_cast<uintptr_t>(mentions.size()),
        static_cast<uintptr_t>(root_mention),
        message.data(),
        static_cast<uintptr_t>(message.size()),
        payer_ptr,
        &result
    );

    free_identities();

    if (error != FfiOperationError_Success) {
        fprintf(stderr, "send_generic_public_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(
            nullptr, std::string("send_generic_public_transaction: wallet FFI error ") + std::to_string(error)
        );
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
}

std::string LEZCoreModule::send_generic_private_transaction(
    const std::vector<std::string>& account_ids,
    const uint64_t root_mention,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& program_elf,
    const std::string& program_kind_json,
    const std::vector<std::vector<uint8_t>>& program_dependencies,
    const std::vector<std::string>& dependency_kinds_json,
    const std::vector<std::string>& actor_state_program_account_ids_hex
) {
    PrivateSendAccounts accounts;
    std::string error;
    if (!resolveOwnedPrivateAccounts(walletHandle, account_ids, accounts, error)) {
        return transferResultToJson(nullptr, "send_generic_private_transaction: " + error);
    }

    return sendGenericPrivateTransaction(
        walletHandle,
        "send_generic_private_transaction",
        accounts.identities,
        root_mention,
        message,
        program_elf,
        program_kind_json,
        program_dependencies,
        dependency_kinds_json,
        actor_state_program_account_ids_hex
    );
}

std::string LEZCoreModule::send_generic_private_transaction_with_accounts(
    const std::vector<std::string>& accounts_json,
    const uint64_t root_mention,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& program_elf,
    const std::string& program_kind_json,
    const std::vector<std::vector<uint8_t>>& program_dependencies,
    const std::vector<std::string>& dependency_kinds_json,
    const std::vector<std::string>& actor_state_program_account_ids_hex
) {
    PrivateSendAccounts accounts;
    std::string error;
    for (size_t i = 0; i < accounts_json.size(); ++i) {
        std::string account_error;
        if (!resolveDescribedAccount(walletHandle, accounts_json[i], accounts, account_error)) {
            error = "accounts_json[" + std::to_string(i) + "] " + account_error;
            return transferResultToJson(nullptr, "send_generic_private_transaction: " + error);
        }
    }

    return sendGenericPrivateTransaction(
        walletHandle,
        "send_generic_private_transaction_with_accounts",
        accounts.identities,
        root_mention,
        message,
        program_elf,
        program_kind_json,
        program_dependencies,
        dependency_kinds_json,
        actor_state_program_account_ids_hex
    );
}

// clang-format off
std::string LEZCoreModule::send_program_deployment_transaction(const std::string& header_account_id_hex, const std::vector<std::string>& segment_account_ids_hex, const std::vector<uint8_t>& program_elf, bool immutable, const std::string& payer_account_id_hex) {
    // clang-format on
    FfiBytes32 header{};
    if (!hexToBytes32(header_account_id_hex, &header)) {
        fprintf(stderr, "send_program_deployment_transaction: invalid header_account_id_hex\n");
        return transferResultToJson(nullptr, "send_program_deployment_transaction: invalid header_account_id_hex");
    }
    FfiBytes32 payer{};
    const FfiBytes32* payer_ptr = nullptr;
    if (!payer_account_id_hex.empty()) {
        if (!hexToBytes32(payer_account_id_hex, &payer)) {
            fprintf(stderr, "send_program_deployment_transaction: invalid payer_account_id_hex\n");
            return transferResultToJson(nullptr, "send_program_deployment_transaction: invalid payer_account_id_hex");
        }
        payer_ptr = &payer;
    }
    std::vector<FfiBytes32> segments(segment_account_ids_hex.size());
    for (size_t i = 0; i < segment_account_ids_hex.size(); ++i) {
        if (!hexToBytes32(segment_account_ids_hex[i], &segments[i])) {
            fprintf(stderr, "send_program_deployment_transaction: invalid segment_account_ids_hex[%zu]\n", i);
            return transferResultToJson(
                nullptr, "send_program_deployment_transaction: invalid segment_account_ids_hex"
            );
        }
    }

    FfiTransactionResult result{};
    const FfiOperationError error = wallet_ffi_program_loader_deploy(
        walletHandle,
        &header,
        segments.data(),
        static_cast<uintptr_t>(segments.size()),
        program_elf.data(),
        static_cast<uintptr_t>(program_elf.size()),
        immutable,
        payer_ptr,
        &result
    );

    if (error != FfiOperationError_Success) {
        fprintf(stderr, "send_program_deployment_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(
            nullptr, std::string("send_program_deployment_transaction: wallet FFI error ") + std::to_string(error)
        );
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
}

bool LEZCoreModule::poll_transaction_status(const std::string& tx_hash_hex) {
    FfiBytes32 tx_hash{};
    if (!hexToBytes32(tx_hash_hex, &tx_hash)) {
        fprintf(stderr, "poll_transaction_status: invalid tx_hash_hex\n");
        return false;
    }

    bool is_found = false;

    const FfiOperationError error = wallet_ffi_poll_transaction_status(walletHandle, tx_hash, &is_found);

    if (error != FfiOperationError_Success) {
        fprintf(stderr, "poll_transaction_status: wallet FFI error %d\n", error);
        return false;
    }

    return is_found;
}

// === Wallet Lifecycle ===

int64_t LEZCoreModule::start_sequencer(
    const std::string& config_path
) {
    if (sequencerHandle) {
        fprintf(stderr, "start_sequencer: sequencer is already started\n");
        return {};
    }

    InitializedSequencerServiceFFIResult start_result =
        sequencer_ffi_start_sequencer(
            // Null pointer to produce new runtime.
            nullptr,
            config_path.c_str()
        );
    if (!start_result.value) {
        fprintf(stderr, "start_sequencer: sequencer_ffi_start_sequencer returned null\n");
        return {};
    }

    sequencerHandle = start_result.value;

    return FfiOperationError_Success;
}

int64_t LEZCoreModule::stop_sequencer() {
    if (!sequencerHandle) {
        fprintf(stderr, "stop_sequencer: attempting to stop null pointer\n");
        return FfiOperationError_InternalError;
    }

    FfiOperationError stop_result = sequencer_ffi_stop_sequencer(sequencerHandle);

    return stop_result;
}

void LEZCoreModule::init_logger(const std::string& level) {
    sequencer_ffi_init_logger(level.c_str());
}

std::string LEZCoreModule::create_new(
    const std::string& config_path,
    const std::string& storage_path,
    const std::string& password
) {
    if (!sequencerHandle) {
        fprintf(stderr, "create_new: sequencer is not started\n");
        return {};
    }

    if (walletHandle) {
        fprintf(stderr, "create_new: wallet is already open\n");
        return {};
    }

    FfiCreateWalletOutput create_output =
        wallet_ffi_create_new(config_path.c_str(), storage_path.c_str(), password.c_str(), sequencerHandle);
    if (!create_output.wallet) {
        fprintf(stderr, "create_new: wallet_ffi_create_new returned null\n");
        return {};
    }

    walletHandle = create_output.wallet;
    std::string mnemonic(create_output.mnemonic);

    primitives_ffi_free_cstring(create_output.mnemonic);

    return mnemonic;
}

int64_t LEZCoreModule::restore_storage(const std::string& mnemonic, uint64_t depth) {
    const FfiOperationError error = wallet_ffi_restore_data(walletHandle, mnemonic.c_str(), static_cast<uint32_t>(depth));
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "restore_storage: wallet FFI error %d\n", error);
        return error;
    }

    return FfiOperationError_Success;
}

int64_t LEZCoreModule::open(
    const std::string& config_path,
    const std::string& storage_path,
    const std::string& password
) {
    if (!sequencerHandle) {
        fprintf(stderr, "open: sequencer is not started\n");
        return FfiOperationError_InternalError;
    }

    if (walletHandle) {
        fprintf(stderr, "open: wallet is already open\n");
        return FfiOperationError_InternalError;
    }

    FfiOperationError error = wallet_ffi_open(config_path.c_str(), storage_path.c_str(), sequencerHandle, password.c_str(), &walletHandle);
    if (!walletHandle) {
        fprintf(stderr, "open: wallet_ffi_open returned null\n");
        return error;
    }

    return FfiOperationError_Success;
}

int64_t LEZCoreModule::save() {
    return wallet_ffi_save(walletHandle);
}

// === Configuration ===

std::string LEZCoreModule::get_sequencer_addr() {
    char* addr = wallet_ffi_get_sequencer_addr(walletHandle);
    if (!addr) {
        fprintf(stderr, "get_sequencer_addr: wallet_ffi returned null\n");
        return {};
    }

    std::string value(addr);
    primitives_ffi_free_cstring(addr);
    return value;
}

// === Labels ===

bool LEZCoreModule::check_label_available(const std::string& label) {
    const char* label_c = label.c_str();

    LabelAvailability label_check = wallet_ffi_check_label_available(walletHandle, label_c);

    if (label_check.error != FfiOperationError_Success) {
        fprintf(stderr, "check_label_available: wallet FFI error %d\n", label_check.error);
        return false;
    }

    return label_check.is_available;
}

int64_t LEZCoreModule::add_label(const std::string& label, const std::string& account_id_hex, bool is_private) {
    const char* label_c = label.c_str();

    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "wallet_ffi_add_label: invalid account_id_hex");
        return FfiOperationError::FfiOperationError_InvalidAccountId;
    }

    FfiAccountIdWithPrivacy acc_id_with_privacy = {id, is_private};

    FfiOperationError error = wallet_ffi_add_label(walletHandle, label_c, acc_id_with_privacy);
    if (error != FfiOperationError_Success) {
        fprintf(stderr, "wallet_ffi_add_label failed : wallet FFI error %d\n", error);
    }

    return FfiOperationError_Success;
}

std::string LEZCoreModule::resolve_label(const std::string& label) {
    const char* label_c = label.c_str();

    AccountIdResolvedFromLabel acc_id_res = wallet_ffi_resolve_label(walletHandle, label_c);

    if (acc_id_res.error != FfiOperationError_Success) {
        fprintf(stderr, "wallet_ffi_resolve_label failed : wallet FFI error %d\n", acc_id_res.error);
        return {};
    }

    std::string hexed_account_id = bytes32ToHex(acc_id_res.account_id.account_id);

    if (acc_id_res.account_id.is_private) {
        return "Private/" + hexed_account_id;
    } else {
        return "Public/" + hexed_account_id;
    }
}

std::vector<std::string> LEZCoreModule::get_all_labels_for_account(const std::string& account_id_hex, bool is_private) {
    FfiAccountIdWithPrivacy acc_id_with_privacy;

    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_all_labels_for_account: invalid account_id_hex");
        return {};
    }

    acc_id_with_privacy.account_id = id;
    acc_id_with_privacy.is_private = is_private;

    LabelList label_list = wallet_ffi_get_all_labels_for_account(walletHandle, acc_id_with_privacy);

    if (label_list.error != FfiOperationError_Success) {
        fprintf(stderr, "wallet_ffi_get_all_labels_for_account failed : wallet FFI error %d\n", label_list.error);
        return {};
    }

    std::vector<std::string> result;
    result.reserve(label_list.labels_size);

    for (uintptr_t i = 0; i < label_list.labels_size; ++i) {
        result.emplace_back(label_list.labels_data[i]);
    }

    FfiOperationError err = wallet_ffi_free_label_list(&label_list);

    if (err != FfiOperationError_Success) {
        fprintf(stderr, "wallet_ffi_free_label_list failed : wallet FFI error %d\n", err);
        return {};
    }

    return result;
}
