#include "logos_execution_zone_wallet_module.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

std::string bytesToHex(const uint8_t* data, const size_t length) {
    static const char hexChars[] = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        out.push_back(hexChars[(data[i] >> 4) & 0xF]);
        out.push_back(hexChars[data[i] & 0xF]);
    }
    return out;
}

// Balance from wallet_ffi_get_balance is 16 bytes little-endian (u128). Convert to decimal string for UI.
// Requires __uint128_t (GCC/Clang on 64-bit).
std::string balanceLe16ToDecimalString(const uint8_t* data) {
#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ >= 16
    __uint128_t v = 0;
    for (int i = 0; i < 16; ++i)
        v |= static_cast<__uint128_t>(data[i]) << (i * 8);
    if (v == 0)
        return "0";
    char buf[40];
    int i = 0;
    while (v) {
        buf[i++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    std::reverse(buf, buf + i);
    return std::string(buf, i);
#else
#error "balanceLe16ToDecimalString requires __uint128_t; build with GCC or Clang on 64-bit"
#endif
}

namespace JsonKeys {
constexpr auto TxHash = "tx_hash";
constexpr auto Success = "success";
constexpr auto Error = "error";
constexpr auto ProgramOwner = "program_owner";
constexpr auto Balance = "balance";
constexpr auto Nonce = "nonce";
constexpr auto Data = "data";
constexpr auto NullifierPublicKey = "nullifier_public_key";
constexpr auto ViewingPublicKey = "viewing_public_key";
constexpr auto AccountId = "account_id";
constexpr auto IsPublic = "is_public";
constexpr auto Secrets = "secrets";
} // namespace JsonKeys

bool hexToBytes(const std::string& hex, std::vector<uint8_t>& output_bytes, int expectedLength = -1) {
    // Trim whitespace.
    size_t start = hex.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        output_bytes.clear();
        return expectedLength == -1 || expectedLength == 0;
    }
    size_t end = hex.find_last_not_of(" \t\n\r\f\v");
    std::string trimmed = hex.substr(start, end - start + 1);

    if (trimmed.size() >= 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X'))
        trimmed = trimmed.substr(2);

    if (trimmed.size() % 2 != 0)
        return false;

    std::vector<uint8_t> decoded;
    decoded.reserve(trimmed.size() / 2);
    auto nibble = [](char c, int& out) -> bool {
        if (c >= '0' && c <= '9') { out = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { out = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { out = c - 'A' + 10; return true; }
        return false;
    };
    for (size_t i = 0; i < trimmed.size(); i += 2) {
        int hi = 0, lo = 0;
        if (!nibble(trimmed[i], hi) || !nibble(trimmed[i + 1], lo))
            return false;
        decoded.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    if (expectedLength != -1 && static_cast<int>(decoded.size()) != expectedLength)
        return false;

    output_bytes = std::move(decoded);
    return true;
}

bool hexToU128(const std::string& hex, uint8_t (*output)[16]) {
    std::vector<uint8_t> buffer;
    if (!hexToBytes(hex, buffer, 16))
        return false;
    memcpy(output, buffer.data(), 16);
    return true;
}

std::string bytes32ToHex(const FfiBytes32& bytes) {
    return bytesToHex(bytes.data, 32);
}

bool hexToBytes32(const std::string& hex, FfiBytes32* output_bytes) {
    if (output_bytes == nullptr)
        return false;
    std::vector<uint8_t> buffer;
    if (!hexToBytes(hex, buffer, 32))
        return false;
    memcpy(output_bytes->data, buffer.data(), 32);
    return true;
}

// Builds JSON { success, tx_hash, error } for both success (result + empty error) and failure (nullptr + errorMessage).
std::string transferResultToJson(const FfiTransferResult* result, const std::string& errorMessage) {
    nlohmann::json obj = nlohmann::json::object();
    const bool isError = !errorMessage.empty();
    obj[JsonKeys::Success] = !isError && result && result->success;
    obj[JsonKeys::TxHash] = (!isError && result && result->tx_hash) ? std::string(result->tx_hash) : std::string();
    obj[JsonKeys::Error] = errorMessage;
    return obj.dump();
}

// Builds JSON { success, tx_hash, secrets, error } for both success (result + empty error) and failure (nullptr + errorMessage) in case of generic transaction.
std::string genericTransactionResultToJson(const FfiTransactionResult* result, const std::string& errorMessage) {
    nlohmann::json obj = nlohmann::json::object();
    const bool isError = !errorMessage.empty();
    obj[JsonKeys::Success] = !isError && result && result->success;
    obj[JsonKeys::TxHash] = (!isError && result && result->tx_hash) ? std::string(result->tx_hash) : std::string();
    std::vector<std::string> secrets;
    if (!isError && result && result->secrets_data) {
        for (uintptr_t i = 0; i < result->secrets_size; ++i) {
            secrets.push_back(bytes32ToHex(result->secrets_data[i]));
        }
    }
    obj[JsonKeys::Secrets] = secrets;
    obj[JsonKeys::Error] = errorMessage;
    return obj.dump();
}

std::string ffiAccountToJson(const FfiAccount& account) {
    nlohmann::json obj = nlohmann::json::object();
    obj[JsonKeys::ProgramOwner] = bytesToHex(reinterpret_cast<const uint8_t*>(account.program_owner.data), 32);
    obj[JsonKeys::Balance] = bytesToHex(account.balance.data, 16);
    obj[JsonKeys::Nonce] = bytesToHex(account.nonce.data, 16);
    if (account.data && account.data_len > 0) {
        obj[JsonKeys::Data] = bytesToHex(account.data, account.data_len);
    } else {
        obj[JsonKeys::Data] = "";
    }
    return obj.dump();
}

nlohmann::json ffiAccountListEntryToJson(const FfiAccountListEntry& entry) {
    nlohmann::json obj = nlohmann::json::object();
    obj[JsonKeys::AccountId] = bytes32ToHex(entry.account_id);
    obj[JsonKeys::IsPublic] = entry.is_public;
    return obj;
}

std::string ffiPrivateAccountKeysToJson(const FfiPrivateAccountKeys& keys) {
    nlohmann::json obj = nlohmann::json::object();
    obj[JsonKeys::NullifierPublicKey] = bytes32ToHex(keys.nullifier_public_key);
    if (keys.viewing_public_key && keys.viewing_public_key_len > 0) {
        obj[JsonKeys::ViewingPublicKey] = bytesToHex(keys.viewing_public_key, keys.viewing_public_key_len);
    } else {
        obj[JsonKeys::ViewingPublicKey] = "";
    }
    return obj.dump();
}

bool jsonToFfiPrivateAccountKeys(const std::string& json, FfiPrivateAccountKeys* output_keys) {
    nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
    if (doc.is_discarded() || !doc.is_object())
        return false;

    if (doc.contains(JsonKeys::NullifierPublicKey) && doc[JsonKeys::NullifierPublicKey].is_string()) {
        if (!hexToBytes32(doc[JsonKeys::NullifierPublicKey].get<std::string>(), &output_keys->nullifier_public_key))
            return false;
    }

    if (doc.contains(JsonKeys::ViewingPublicKey) && doc[JsonKeys::ViewingPublicKey].is_string()) {
        std::vector<uint8_t> buffer;
        if (!hexToBytes(doc[JsonKeys::ViewingPublicKey].get<std::string>(), buffer))
            return false;

        if (buffer.empty()) {
            output_keys->viewing_public_key = nullptr;
            output_keys->viewing_public_key_len = 0;
        } else {
            auto* data = static_cast<uint8_t*>(malloc(buffer.size()));
            memcpy(data, buffer.data(), buffer.size());
            output_keys->viewing_public_key = data;
            output_keys->viewing_public_key_len = buffer.size();
        }
    } else {
        output_keys->viewing_public_key = nullptr;
        output_keys->viewing_public_key_len = 0;
    }

    return true;
}

// Parses a JSON array of 32-byte hex strings into a contiguous byte buffer of siblings.
// Returns true on success, with out_len set to the number of siblings and out_bytes sized to out_len*32.
bool jsonArrayHexToSiblings32(const std::string& json_array_str, std::vector<uint8_t>& out_bytes, uintptr_t& out_len) {
    nlohmann::json doc = nlohmann::json::parse(json_array_str, nullptr, false);
    if (doc.is_discarded() || !doc.is_array())
        return false;

    out_len = static_cast<uintptr_t>(doc.size());
    out_bytes.clear();
    out_bytes.reserve(out_len * 32);

    for (const auto& v : doc) {
        if (!v.is_string())
            return false;
        std::vector<uint8_t> bytes;
        if (!hexToBytes(v.get<std::string>(), bytes, 32))
            return false;
        out_bytes.insert(out_bytes.end(), bytes.begin(), bytes.end());
    }
    return true;
}

} // namespace

LogosExecutionZoneWalletModule::LogosExecutionZoneWalletModule() = default;

LogosExecutionZoneWalletModule::~LogosExecutionZoneWalletModule() {
    if (walletHandle) {
        wallet_ffi_destroy(walletHandle);
        walletHandle = nullptr;
    }
}

std::string LogosExecutionZoneWalletModule::name() const {
    return "logos_execution_zone";
}

std::string LogosExecutionZoneWalletModule::version() const {
    return "1.0.0";
}

// === Account Management ===

std::string LogosExecutionZoneWalletModule::create_account_public() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_public(walletHandle, &id);
    if (error != SUCCESS) {
        fprintf(stderr, "create_account_public: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

std::string LogosExecutionZoneWalletModule::create_account_private() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_private(walletHandle, &id);
    if (error != SUCCESS) {
        fprintf(stderr, "create_account_private: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

LogosList LogosExecutionZoneWalletModule::list_accounts() {
    LogosList result = nlohmann::json::array();
    FfiAccountList list{};
    const WalletFfiError error = wallet_ffi_list_accounts(walletHandle, &list);
    if (error != SUCCESS) {
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

std::string LogosExecutionZoneWalletModule::get_balance(const std::string& account_id_hex, const bool is_public) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_balance: invalid account_id_hex\n");
        return {};
    }

    uint8_t balance[16] = {0};
    const WalletFfiError error = wallet_ffi_get_balance(walletHandle, &id, is_public, &balance);
    if (error != SUCCESS) {
        fprintf(stderr, "get_balance: wallet FFI error %d\n", error);
        return {};
    }
    // Return decimal string for UI display (balance is 16-byte little-endian u128).
    return balanceLe16ToDecimalString(balance);
}

std::string LogosExecutionZoneWalletModule::get_account_public(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_account_public: invalid account_id_hex\n");
        return {};
    }
    FfiAccount account{};
    const WalletFfiError error = wallet_ffi_get_account_public(walletHandle, &id, &account);
    if (error != SUCCESS) {
        fprintf(stderr, "get_account_public: wallet FFI error %d\n", error);
        return {};
    }
    std::string result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

std::string LogosExecutionZoneWalletModule::get_account_private(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_account_private: invalid account_id_hex\n");
        return {};
    }
    FfiAccount account{};
    const WalletFfiError error = wallet_ffi_get_account_private(walletHandle, &id, &account);
    if (error != SUCCESS) {
        fprintf(stderr, "get_account_private: wallet FFI error %d\n", error);
        return {};
    }
    std::string result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

std::string LogosExecutionZoneWalletModule::get_public_account_key(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_public_account_key: invalid account_id_hex\n");
        return {};
    }
    FfiPublicAccountKey key{};
    const WalletFfiError error = wallet_ffi_get_public_account_key(walletHandle, &id, &key);
    if (error != SUCCESS) {
        fprintf(stderr, "get_public_account_key: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(key.public_key);
}

std::string LogosExecutionZoneWalletModule::get_private_account_keys(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "get_private_account_keys: invalid account_id_hex\n");
        return {};
    }
    FfiPrivateAccountKeys keys{};
    const WalletFfiError error = wallet_ffi_get_private_account_keys(walletHandle, &id, &keys);
    if (error != SUCCESS) {
        fprintf(stderr, "get_private_account_keys: wallet FFI error %d\n", error);
        return {};
    }
    std::string result = ffiPrivateAccountKeysToJson(keys);
    wallet_ffi_free_private_account_keys(&keys);
    return result;
}

// === Account Encoding ===

std::string LogosExecutionZoneWalletModule::account_id_to_base58(const std::string& account_id_hex) {
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
    wallet_ffi_free_string(str);
    return value;
}

std::string LogosExecutionZoneWalletModule::account_id_from_base58(const std::string& base58_str) {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_account_id_from_base58(base58_str.c_str(), &id);
    if (error != SUCCESS) {
        fprintf(stderr, "account_id_from_base58: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

// === Blockchain Synchronisation ===

int64_t LogosExecutionZoneWalletModule::sync_to_block(const int64_t block_id) {
    return wallet_ffi_sync_to_block(walletHandle, static_cast<uint64_t>(block_id));
}

int64_t LogosExecutionZoneWalletModule::get_last_synced_block() {
    uint64_t block_id = 0;
    const WalletFfiError error = wallet_ffi_get_last_synced_block(walletHandle, &block_id);
    if (error != SUCCESS) {
        fprintf(stderr, "get_last_synced_block: wallet FFI error %d\n", error);
        return 0;
    }
    return static_cast<int64_t>(block_id);
}

int64_t LogosExecutionZoneWalletModule::get_current_block_height() {
    uint64_t block_height = 0;
    const WalletFfiError error = wallet_ffi_get_current_block_height(walletHandle, &block_height);
    if (error != SUCCESS) {
        fprintf(stderr, "get_current_block_height: wallet FFI error %d\n", error);
        return 0;
    }
    return static_cast<int64_t>(block_height);
}

// === Pinata claiming ===

std::string LogosExecutionZoneWalletModule::claim_pinata(
    const std::string& pinata_account_id_hex,
    const std::string& winner_account_id_hex,
    const std::string& solution_le16_hex
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        fprintf(stderr, "claim_pinata: invalid account id hex\n");
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        fprintf(stderr, "claim_pinata: solution_le16_hex must be 32 hex characters (16 bytes)\n");
        return {};
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_claim_pinata(walletHandle, &pinataId, &winnerId, &solution, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "claim_pinata: wallet FFI error %d\n", error);
        return {};
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::claim_pinata_private_owned_already_initialized(
    const std::string& pinata_account_id_hex,
    const std::string& winner_account_id_hex,
    const std::string& solution_le16_hex,
    int64_t winner_proof_index,
    const std::string& winner_proof_siblings_json
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        fprintf(stderr, "claim_pinata_private_owned_already_initialized: invalid account id hex\n");
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        fprintf(stderr, "claim_pinata_private_owned_already_initialized: solution_le16_hex must be 32 hex characters (16 bytes)\n");
        return {};
    }

    std::vector<uint8_t> siblings_bytes;
    uintptr_t siblings_len = 0;
    if (!jsonArrayHexToSiblings32(winner_proof_siblings_json, siblings_bytes, siblings_len)) {
        fprintf(stderr, "claim_pinata_private_owned_already_initialized: failed to parse winner_proof_siblings_json\n");
        return {};
    }

    const uint8_t (*siblings_ptr)[32] = nullptr;
    if (siblings_len > 0) {
        siblings_ptr = reinterpret_cast<const uint8_t (*)[32]>(siblings_bytes.data());
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_claim_pinata_private_owned_already_initialized(
        walletHandle,
        &pinataId,
        &winnerId,
        &solution,
        static_cast<uintptr_t>(winner_proof_index),
        siblings_ptr,
        siblings_len,
        &result
    );
    if (error != SUCCESS) {
        fprintf(stderr, "claim_pinata_private_owned_already_initialized: wallet FFI error %d\n", error);
        return {};
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::claim_pinata_private_owned_not_initialized(
    const std::string& pinata_account_id_hex,
    const std::string& winner_account_id_hex,
    const std::string& solution_le16_hex
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        fprintf(stderr, "claim_pinata_private_owned_not_initialized: invalid account id hex\n");
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        fprintf(stderr, "claim_pinata_private_owned_not_initialized: solution_le16_hex must be 32 hex characters (16 bytes)\n");
        return {};
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_claim_pinata_private_owned_not_initialized(
        walletHandle,
        &pinataId,
        &winnerId,
        &solution,
        &result
    );
    if (error != SUCCESS) {
        fprintf(stderr, "claim_pinata_private_owned_not_initialized: wallet FFI error %d\n", error);
        return {};
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

// === Operations ===

std::string LogosExecutionZoneWalletModule::transfer_public(
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
    const WalletFfiError error = wallet_ffi_transfer_public(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_public: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_public: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::transfer_shielded(
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
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return transferResultToJson(nullptr, "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // Bandaid, I am not sure, how exactly identifiers should be used.
    FfiU128 identifier {};
    // Keycart not yet supported
    const char *key_path = nullptr;

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_shielded(walletHandle, &fromId, &toKeys, &identifier, &amount, key_path, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_shielded: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_shielded: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::transfer_deshielded(
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
        return transferResultToJson(nullptr, "transfer_deshielded: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_deshielded(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_deshielded: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_deshielded: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::transfer_private(
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
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return transferResultToJson(nullptr, "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // Bandaid, I am not sure, how exactly identifiers should be used.
    FfiU128 identifier {};

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_private(walletHandle, &fromId, &toKeys, &identifier, &amount, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_private: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_private: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::transfer_shielded_owned(
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
        return transferResultToJson(nullptr, "transfer_shielded_owned: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // Keycart not yet supported
    const char *key_path = nullptr;

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_shielded_owned(walletHandle, &fromId, &toId, &amount, key_path, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_shielded_owned: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_shielded_owned: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::transfer_private_owned(
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
        return transferResultToJson(nullptr, "transfer_private_owned: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_private_owned(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "transfer_private_owned: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "transfer_private_owned: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::register_public_account(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "register_public_account: invalid account_id_hex\n");
        return transferResultToJson(nullptr, "register_public_account: invalid account_id_hex");
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_register_public_account(walletHandle, &id, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "register_public_account: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "register_public_account: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::register_private_account(const std::string& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        fprintf(stderr, "register_private_account: invalid account_id_hex\n");
        return transferResultToJson(nullptr, "register_private_account: invalid account_id_hex");
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_register_private_account(walletHandle, &id, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "register_private_account: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "register_private_account: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::vector<uint8_t> LogosExecutionZoneWalletModule::token_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_token_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "token_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data,
                                 ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::vector<uint8_t> LogosExecutionZoneWalletModule::amm_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_token_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "amm_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data,
                                 ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::vector<uint8_t> LogosExecutionZoneWalletModule::ata_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_token_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "ata_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data,
                                 ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::vector<uint8_t> LogosExecutionZoneWalletModule::authenticated_transfer_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_token_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "authenticated_transfer_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data,
                                 ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::string LogosExecutionZoneWalletModule::send_generic_public_transaction(
        const std::vector<std::string>& account_ids,
        const std::vector<bool>& signing_requirements, 
        const std::vector<uint32_t>& instruction,
        const std::vector<uint8_t>& program_elf,
        const std::vector<std::vector<uint8_t>>& program_dependencies
) {
    std::vector<FfiAccountIdentity> identities_resolved;
    identities_resolved.reserve(account_ids.size());

    for (int i = 0; i < account_ids.size(); ++i) {
        FfiAccountIdentity acc_identity{};

        FfiBytes32 id{};
        if (!hexToBytes32(account_ids[i], &id)) {
            fprintf(stderr, "wallet_ffi_resolve_public_account: invalid account_id_hex");
            return transferResultToJson(nullptr, std::string("wallet_ffi_resolve_public_account: invalid account_id_hex"));
        }

        WalletFfiError error = wallet_ffi_resolve_public_account(id, signing_requirements[i], &acc_identity);
        if (error != SUCCESS) {
            fprintf(stderr, "wallet_ffi_resolve_public_account failed for index %d: wallet FFI error %d\n", i, error);
            return transferResultToJson(nullptr, std::string("wallet_ffi_resolve_public_account: wallet FFI error ") + std::to_string(error));
        }
        identities_resolved.push_back(acc_identity);
    }

    const FfiAccountIdentity *account_identities = identities_resolved.data();
    uintptr_t account_identities_size = static_cast<uintptr_t>(identities_resolved.size());

    const uint32_t* input_instruction_data = instruction.data();
    uintptr_t input_instruction_data_size = static_cast<uintptr_t>(instruction.size());

    FfiProgram main_program {};

    const uint8_t *program_elf_data = program_elf.data();
    uintptr_t program_elf_size = static_cast<uintptr_t>(program_elf.size());

    main_program.elf_data = program_elf_data;
    main_program.elf_size = program_elf_size;

    std::vector<FfiProgram> ffi_program_dependencies;
    ffi_program_dependencies.reserve(program_dependencies.size());

    for (int i = 0; i < program_dependencies.size(); ++i) {
        FfiProgram program{};

        const uint8_t *program_elf_data = program_dependencies[i].data();
        uintptr_t program_elf_size = static_cast<uintptr_t>(program_dependencies[i].size());

        program.elf_data = program_elf_data;
        program.elf_size = program_elf_size;

        ffi_program_dependencies.push_back(program);
    }

    const FfiProgram *dependencies_data = ffi_program_dependencies.data();
    uintptr_t dependencies_size = static_cast<uintptr_t>(ffi_program_dependencies.size());

    FfiProgramWithDependencies program_with_dependencies {};

    program_with_dependencies.program = main_program;
    program_with_dependencies.deps = dependencies_data;
    program_with_dependencies.deps_size = dependencies_size;

    FfiTransactionResult result {};

    const WalletFfiError error = wallet_ffi_send_generic_public_transaction(
        walletHandle, 
        account_identities,
        account_identities_size,
        input_instruction_data, 
        input_instruction_data_size,
        &program_with_dependencies,
        &result
    );

    for (FfiAccountIdentity& acc_identity : identities_resolved) {
        wallet_ffi_free_account_identity(&acc_identity);
    }

    if (error != SUCCESS) {
        fprintf(stderr, "send_generic_public_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, std::string("send_generic_public_transaction: wallet FFI error ") + std::to_string(error));
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::send_generic_private_transaction(
        const std::vector<std::string>& account_ids,
        const std::vector<uint32_t>& instruction,
        const std::vector<uint8_t>& program_elf,
        const std::vector<std::vector<uint8_t>>& program_dependencies
) {
    std::vector<FfiAccountIdentity> identities_resolved;
    identities_resolved.reserve(account_ids.size());

    for (int i = 0; i < account_ids.size(); ++i) {
        FfiAccountIdentity acc_identity{};

        FfiBytes32 id{};
        if (!hexToBytes32(account_ids[i], &id)) {
            fprintf(stderr, "wallet_ffi_resolve_private_account: invalid account_id_hex");
            return transferResultToJson(nullptr, std::string("wallet_ffi_resolve_private_account: invalid account_id_hex"));
        }

        WalletFfiError error = wallet_ffi_resolve_private_account(walletHandle, id, &acc_identity);
        if (error != SUCCESS) {
            fprintf(stderr, "wallet_ffi_resolve_private_account failed for index %d: wallet FFI error %d\n", i, error);
            return transferResultToJson(nullptr, std::string("wallet_ffi_resolve_private_account: wallet FFI error ") + std::to_string(error));
        }
        identities_resolved.push_back(acc_identity);
    }

    const FfiAccountIdentity *account_identities = identities_resolved.data();
    uintptr_t account_identities_size = static_cast<uintptr_t>(identities_resolved.size());

    const uint32_t* input_instruction_data = instruction.data();
    uintptr_t input_instruction_data_size = static_cast<uintptr_t>(instruction.size());

    FfiProgram main_program {};

    const uint8_t *program_elf_data = program_elf.data();
    uintptr_t program_elf_size = static_cast<uintptr_t>(program_elf.size());

    main_program.elf_data = program_elf_data;
    main_program.elf_size = program_elf_size;

    std::vector<FfiProgram> ffi_program_dependencies;
    ffi_program_dependencies.reserve(program_dependencies.size());

    for (int i = 0; i < program_dependencies.size(); ++i) {
        FfiProgram program{};

        const uint8_t *program_elf_data = program_dependencies[i].data();
        uintptr_t program_elf_size = static_cast<uintptr_t>(program_dependencies[i].size());

        program.elf_data = program_elf_data;
        program.elf_size = program_elf_size;

        ffi_program_dependencies.push_back(program);
    }

    const FfiProgram *dependencies_data = ffi_program_dependencies.data();
    uintptr_t dependencies_size = static_cast<uintptr_t>(ffi_program_dependencies.size());

    FfiProgramWithDependencies program_with_dependencies {};

    program_with_dependencies.program = main_program;
    program_with_dependencies.deps = dependencies_data;
    program_with_dependencies.deps_size = dependencies_size;

    FfiTransactionResult result {};

    const WalletFfiError error = wallet_ffi_send_generic_private_transaction(
        walletHandle, 
        account_identities,
        account_identities_size,
        input_instruction_data, 
        input_instruction_data_size,
        &program_with_dependencies,
        &result
    );

    for (FfiAccountIdentity& acc_identity : identities_resolved) {
        wallet_ffi_free_account_identity(&acc_identity);
    }

    if (error != SUCCESS) {
        fprintf(stderr, "send_generic_private_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, std::string("send_generic_private_transaction: wallet FFI error ") + std::to_string(error));
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
}

std::string LogosExecutionZoneWalletModule::send_program_deployment_transaction(
        const std::vector<uint8_t>& program_elf
) {
    FfiTransactionResult result {};

    const uint8_t *program_elf_data = program_elf.data();
    uintptr_t program_elf_size = static_cast<uintptr_t>(program_elf.size());

    const WalletFfiError error = wallet_ffi_program_deployment(
        walletHandle, 
        program_elf_data,
        program_elf_size,
        &result
    );

    if (error != SUCCESS) {
        fprintf(stderr, "send_program_deployment_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, std::string("send_program_deployment_transaction: wallet FFI error ") + std::to_string(error));
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
}

// === Wallet Lifecycle ===

std::string LogosExecutionZoneWalletModule::create_new(
    const std::string& config_path,
    const std::string& storage_path,
    const std::string& password
) {
    if (walletHandle) {
        fprintf(stderr, "create_new: wallet is already open\n");
        return {};
    }

    FfiCreateWalletResult create_result = wallet_ffi_create_new(config_path.c_str(), storage_path.c_str(), password.c_str());
    if (!create_result.wallet) {
        fprintf(stderr, "create_new: wallet_ffi_create_new returned null\n");
        return {};
    }

    walletHandle = create_result.wallet;
    std::string mnemonic = *create_result.mnemonic;

    return mnemonic;
}

int64_t LogosExecutionZoneWalletModule::restore_storage(const std::string& mnemonic, const std::string password) {
    const WalletFfiError error = wallet_ffi_restore_data(walletHandle, mnemonic.c_str(), password.c_str());
    if (error != SUCCESS) {
        fprintf(stderr, "restore_storage: wallet FFI error %d\n", error);
        return error;
    }

    return SUCCESS;
}

int64_t LogosExecutionZoneWalletModule::open(const std::string& config_path, const std::string& storage_path) {
    if (walletHandle) {
        fprintf(stderr, "open: wallet is already open\n");
        return INTERNAL_ERROR;
    }

    walletHandle = wallet_ffi_open(config_path.c_str(), storage_path.c_str());
    if (!walletHandle) {
        fprintf(stderr, "open: wallet_ffi_open returned null\n");
        return INTERNAL_ERROR;
    }

    return SUCCESS;
}

int64_t LogosExecutionZoneWalletModule::save() {
    return wallet_ffi_save(walletHandle);
}

// === Configuration ===

std::string LogosExecutionZoneWalletModule::get_sequencer_addr() {
    char* addr = wallet_ffi_get_sequencer_addr(walletHandle);
    if (!addr) {
        fprintf(stderr, "get_sequencer_addr: wallet_ffi returned null\n");
        return {};
    }

    std::string value(addr);
    wallet_ffi_free_string(addr);
    return value;
}