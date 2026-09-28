#include "lez_core_module.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
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
        constexpr auto Nonce = "nonce";
        constexpr auto Shards = "shards";
        constexpr auto Program = "program";
        constexpr auto Data = "data";
        constexpr auto NullifierPublicKey = "nullifier_public_key";
        constexpr auto ViewingPublicKey = "viewing_public_key";
        constexpr auto Identifier = "identifier";
        constexpr auto AccountId = "account_id";
        constexpr auto IsPublic = "is_public";
        constexpr auto Secrets = "secrets";
        constexpr auto Kind = "kind";
        constexpr auto KindDisclosed = "disclosed";
        constexpr auto KindShadow = "shadow";
        constexpr auto KindUndisclosed = "undisclosed";
        constexpr auto ProgramHeader = "program_header";
        constexpr auto ImageIdHex = "image_id_hex";
        constexpr auto ProgramFirstSegmentHex = "program_first_segment_hex";
        constexpr auto Immutable = "immutable";
        constexpr auto MembershipProof = "membership_proof";
        constexpr auto Index = "index";
        constexpr auto Path = "path";
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
            if (c >= '0' && c <= '9') {
                out = c - '0';
                return true;
            }
            if (c >= 'a' && c <= 'f') {
                out = c - 'a' + 10;
                return true;
            }
            if (c >= 'A' && c <= 'F') {
                out = c - 'A' + 10;
                return true;
            }
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

    // Builds JSON { success, tx_hash, error } for both success (result + empty error) and failure (nullptr +
    // errorMessage).
    std::string transferResultToJson(const FfiTransferResult* result, const std::string& errorMessage) {
        nlohmann::json obj = nlohmann::json::object();
        const bool isError = !errorMessage.empty();
        obj[JsonKeys::Success] = !isError && result && result->success;
        obj[JsonKeys::TxHash] = (!isError && result && result->tx_hash) ? std::string(result->tx_hash) : std::string();
        obj[JsonKeys::Error] = errorMessage;
        return obj.dump();
    }

    // Builds JSON { success, tx_hash, secrets, error } for both success (result + empty error) and failure (nullptr +
    // errorMessage) in case of generic transaction.
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

    // Builds JSON { nonce, shards: [{ program, data }] }.
    std::string ffiAccountToJson(const FfiAccount& account) {
        nlohmann::json obj = nlohmann::json::object();
        obj[JsonKeys::Nonce] = bytesToHex(account.nonce.data, 16);
        nlohmann::json shards = nlohmann::json::array();
        for (uintptr_t i = 0; account.shards && i < account.shards_len; ++i) {
            const FfiShard& shard = account.shards[i];
            nlohmann::json shardObj = nlohmann::json::object();
            shardObj[JsonKeys::Program] = bytes32ToHex(shard.program);
            shardObj[JsonKeys::Data] =
                (shard.data && shard.data_len > 0) ? bytesToHex(shard.data, shard.data_len) : std::string();
            shards.push_back(shardObj);
        }
        obj[JsonKeys::Shards] = shards;
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

    // Nothing in this codebase currently emits an "identifier" field in to_keys_json — NPK/VPK
    // identify a key group, not one specific account in it, so get_private_account_keys never
    // attaches one. Kept for forward compatibility (e.g. a hand-crafted or future payload that
    // targets one specific account within a group) and to make the fallback below explicit.
    bool jsonExtractIdentifier(const std::string& json, FfiIdentifier* out_identifier) {
        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object())
            return false;
        if (!doc.contains(JsonKeys::Identifier) || !doc[JsonKeys::Identifier].is_string())
            return false;
        return hexToBytes32(doc[JsonKeys::Identifier].get<std::string>(), out_identifier);
    }

    // A foreign recipient's identifier isn't known to the sender; the recipient's wallet
    // recovers it from the encrypted transfer payload the next time it runs sync-private.
    FfiIdentifier randomFfiIdentifier() {
        static std::mt19937_64 rng(std::random_device{}());
        FfiIdentifier value{};
        for (size_t i = 0; i < sizeof(value.data); i += 8) {
            uint64_t chunk = rng();
            memcpy(value.data + i, &chunk, sizeof(chunk));
        }
        return value;
    }

    bool jsonToFfiPrivateAccountKeys(const std::string& json, FfiPrivateAccountKeys* output_keys) {
        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object())
            return false;

        // Nullifier public key is mandatory: a missing/wrong-typed value must not fall back to zero.
        if (!doc.contains(JsonKeys::NullifierPublicKey) || !doc[JsonKeys::NullifierPublicKey].is_string())
            return false;
        if (!hexToBytes32(doc[JsonKeys::NullifierPublicKey].get<std::string>(), &output_keys->nullifier_public_key))
            return false;

        output_keys->viewing_public_key = nullptr;
        output_keys->viewing_public_key_len = 0;

        if (doc.contains(JsonKeys::ViewingPublicKey)) {
            if (!doc[JsonKeys::ViewingPublicKey].is_string())
                return false;

            std::vector<uint8_t> buffer;
            if (!hexToBytes(doc[JsonKeys::ViewingPublicKey].get<std::string>(), buffer))
                return false;

            if (!buffer.empty()) {
                auto* data = static_cast<uint8_t*>(malloc(buffer.size()));
                if (!data)
                    return false;
                memcpy(data, buffer.data(), buffer.size());
                output_keys->viewing_public_key = data;
                output_keys->viewing_public_key_len = buffer.size();
            }
        }

        return true;
    }

    // Parses a JSON array of 32-byte hex strings into a contiguous byte buffer of siblings.
    // Returns true on success, with out_len set to the number of siblings and out_bytes sized to out_len*32.
    bool jsonArrayHexToSiblings32(
        const std::string& json_array_str,
        std::vector<uint8_t>& out_bytes,
        uintptr_t& out_len
    ) {
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

    // FfiMembershipProof.path points into proof_path_bytes, which must outlive it.
    struct ParsedProgramKind {
        FfiProgramKind kind{};
        // Required for disclosed/undisclosed; optional for shadow (the FFI derives its address).
        bool has_account_id = false;
        FfiBytes32 account_id{};
        FfiProgramHeader program_header{};
        std::vector<uint8_t> proof_path_bytes;
        FfiMembershipProof membership_proof{};
    };

    bool jsonToProgramKind(const std::string& json, ParsedProgramKind* out) {
        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object())
            return false;
        if (!doc.contains(JsonKeys::Kind) || !doc[JsonKeys::Kind].is_string())
            return false;

        const std::string kindStr = doc[JsonKeys::Kind].get<std::string>();
        if (kindStr == JsonKeys::KindDisclosed)
            out->kind = FfiProgramKind::PROGRAM_DISCLOSED;
        else if (kindStr == JsonKeys::KindShadow)
            out->kind = FfiProgramKind::PROGRAM_SHADOW;
        else if (kindStr == JsonKeys::KindUndisclosed)
            out->kind = FfiProgramKind::PROGRAM_UNDISCLOSED;
        else
            return false;

        if (doc.contains(JsonKeys::AccountId)) {
            if (!doc[JsonKeys::AccountId].is_string())
                return false;
            if (!hexToBytes32(doc[JsonKeys::AccountId].get<std::string>(), &out->account_id))
                return false;
            out->has_account_id = true;
        }

        if (out->kind == FfiProgramKind::PROGRAM_SHADOW)
            return true;
        if (!out->has_account_id)
            return false;
        if (out->kind == FfiProgramKind::PROGRAM_DISCLOSED)
            return true;

        if (!doc.contains(JsonKeys::ProgramHeader) || !doc[JsonKeys::ProgramHeader].is_object())
            return false;
        const auto& header = doc[JsonKeys::ProgramHeader];

        if (!header.contains(JsonKeys::ImageIdHex) || !header[JsonKeys::ImageIdHex].is_string())
            return false;
        if (!hexToBytes32(header[JsonKeys::ImageIdHex].get<std::string>(), &out->program_header.image_id))
            return false;

        if (!header.contains(JsonKeys::ProgramFirstSegmentHex) || !header[JsonKeys::ProgramFirstSegmentHex].is_string())
            return false;
        if (!hexToBytes32(
                header[JsonKeys::ProgramFirstSegmentHex].get<std::string>(), &out->program_header.program_first_segment
            ))
            return false;

        if (!header.contains(JsonKeys::Immutable) || !header[JsonKeys::Immutable].is_boolean())
            return false;
        out->program_header.immutable = header[JsonKeys::Immutable].get<bool>();

        if (!doc.contains(JsonKeys::MembershipProof) || !doc[JsonKeys::MembershipProof].is_object())
            return false;
        const auto& proof = doc[JsonKeys::MembershipProof];

        if (!proof.contains(JsonKeys::Index) || !proof[JsonKeys::Index].is_number_unsigned())
            return false;
        out->membership_proof.index = proof[JsonKeys::Index].get<uintptr_t>();

        if (!proof.contains(JsonKeys::Path) || !proof[JsonKeys::Path].is_array())
            return false;
        uintptr_t path_len = 0;
        if (!jsonArrayHexToSiblings32(proof[JsonKeys::Path].dump(), out->proof_path_bytes, path_len))
            return false;
        out->membership_proof.path = reinterpret_cast<const FfiBytes32*>(out->proof_path_bytes.data());
        out->membership_proof.path_len = path_len;

        return true;
    }

    // Mentions borrow the identities' heap fields; free the identities only after use.
    bool buildAccountMentions(
        const std::vector<FfiAccountIdentity>& identities,
        const std::vector<std::string>& shard_program_account_ids_hex,
        const FfiBytes32* default_shard,
        std::vector<FfiAccountMention>& out_mentions,
        std::string& out_error
    ) {
        if (!shard_program_account_ids_hex.empty() && shard_program_account_ids_hex.size() != identities.size()) {
            out_error = "shard_program_account_ids_hex must be empty or match account_ids in size";
            return false;
        }

        out_mentions.clear();
        out_mentions.reserve(identities.size());
        for (size_t i = 0; i < identities.size(); ++i) {
            FfiAccountMention mention{};
            mention.identity = identities[i];

            const bool hasOverride =
                !shard_program_account_ids_hex.empty() && !shard_program_account_ids_hex[i].empty();
            if (hasOverride) {
                if (!hexToBytes32(shard_program_account_ids_hex[i], &mention.program_account_id)) {
                    out_error = "invalid shard_program_account_ids_hex[" + std::to_string(i) + "]";
                    return false;
                }
            } else if (default_shard) {
                mention.program_account_id = *default_shard;
            } else {
                out_error =
                    "shard_program_account_ids_hex[" + std::to_string(i) +
                    "] is required when the root program's account id is unknown (shadow root without account_id)";
                return false;
            }
            out_mentions.push_back(mention);
        }
        return true;
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
    return "0.3.0";
}

// === Wallet Location ===

std::string LEZCoreModule::wallet_dir() {
    if (!isContextReady() || instancePersistencePath().empty())
        return LEZ_NO_WALLET_DIR;
    return instancePersistencePath();
}

// === Account Management ===

std::string LEZCoreModule::create_account_public() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_public(walletHandle, &id);
    if (error != SUCCESS) {
        fprintf(stderr, "create_account_public: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

std::string LEZCoreModule::create_account_private() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_private(walletHandle, &id);
    if (error != SUCCESS) {
        fprintf(stderr, "create_account_private: wallet FFI error %d\n", error);
        return {};
    }
    return bytes32ToHex(id);
}

LogosList LEZCoreModule::list_accounts() {
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

std::string LEZCoreModule::get_balance(const std::string& account_id_hex, const bool is_public) {
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

std::string LEZCoreModule::get_account_public(const std::string& account_id_hex) {
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

std::string LEZCoreModule::get_account_private(const std::string& account_id_hex) {
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

std::string LEZCoreModule::get_public_account_key(const std::string& account_id_hex) {
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

std::string LEZCoreModule::get_private_account_keys(const std::string& account_id_hex) {
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

    // NPK/VPK identify the key group a private account belongs to, not one specific
    // account within it — there's no real identifier to attach here. (wallet_ffi_resolve_private_account
    // can't supply one either: for a regular owned account it returns AccountIdentity::PrivateOwned,
    // which carries no identifier and defaults to zero — not a real value.)
    std::string result = ffiPrivateAccountKeysToJson(keys);
    wallet_ffi_free_private_account_keys(&keys);
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
    wallet_ffi_free_string(str);
    return value;
}

std::string LEZCoreModule::account_id_from_base58(const std::string& base58_str) {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_account_id_from_base58(base58_str.c_str(), &id);
    if (error != SUCCESS) {
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
    const WalletFfiError error = wallet_ffi_get_last_synced_block(walletHandle, &block_id);
    if (error != SUCCESS) {
        fprintf(stderr, "get_last_synced_block: wallet FFI error %d\n", error);
        return 0;
    }
    return static_cast<int64_t>(block_id);
}

int64_t LEZCoreModule::get_current_block_height() {
    uint64_t block_height = 0;
    const WalletFfiError error = wallet_ffi_get_current_block_height(walletHandle, &block_height);
    if (error != SUCCESS) {
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
    const WalletFfiError error = wallet_ffi_transfer_public(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
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
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return transferResultToJson(nullptr, "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // to_keys_json never carries an identifier in this codebase (NPK/VPK name a key group,
    // not one account in it) — pick a random one, which the recipient's wallet will recover
    // from the encrypted transfer payload on its next sync-private. See jsonExtractIdentifier.
    FfiIdentifier toIdentifier{};
    if (!jsonExtractIdentifier(to_keys_json, &toIdentifier))
        toIdentifier = randomFfiIdentifier();
    // TODO: Add keycard support
    const char* key_path = nullptr;

    FfiTransferResult result{};
    const WalletFfiError error =
        wallet_ffi_transfer_shielded(walletHandle, &fromId, &toKeys, &toIdentifier, &amount, key_path, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
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
    const WalletFfiError error = wallet_ffi_transfer_deshielded(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
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
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return transferResultToJson(nullptr, "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)");
    }

    // See transfer_shielded above: to_keys_json never carries an identifier, so always pick
    // a random one for the recipient's wallet to recover via sync-private.
    FfiIdentifier toIdentifier{};
    if (!jsonExtractIdentifier(to_keys_json, &toIdentifier))
        toIdentifier = randomFfiIdentifier();
    FfiTransferResult result{};
    const WalletFfiError error =
        wallet_ffi_transfer_private(walletHandle, &fromId, &toKeys, &toIdentifier, &amount, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
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
    const WalletFfiError error =
        wallet_ffi_transfer_shielded_owned(walletHandle, &fromId, &toId, &amount, key_path, &result);
    if (error != SUCCESS) {
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
    const WalletFfiError error = wallet_ffi_transfer_private_owned(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
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
    const WalletFfiError error = wallet_ffi_bridge_withdraw(walletHandle, &fromId, amount, &bedrockAccountPk, &result);
    if (error != SUCCESS) {
        fprintf(stderr, "bridge_withdraw: wallet FFI error %d\n", error);
        return transferResultToJson(nullptr, "bridge_withdraw: wallet FFI error " + std::to_string(error));
    }
    std::string resultJson = transferResultToJson(&result, std::string());
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

std::vector<uint8_t> LEZCoreModule::token_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_token_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "token_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data, ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::vector<uint8_t> LEZCoreModule::amm_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_amm_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "amm_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data, ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::vector<uint8_t> LEZCoreModule::ata_elf() {
    FfiProgram ffi_program{};
    WalletFfiError error = wallet_ffi_ata_elf(&ffi_program);
    if (error != SUCCESS) {
        fprintf(stderr, "ata_elf: wallet FFI error %d\n", error);
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> result(ffi_program.elf_data, ffi_program.elf_data + ffi_program.elf_size);

    wallet_ffi_free_ffi_program(&ffi_program);
    return result;
}

std::string LEZCoreModule::send_generic_public_transaction(
    const std::vector<std::string>& account_ids,
    const std::vector<bool>& signing_requirements,
    const std::vector<uint8_t>& instruction,
    const std::string& program_id_hex,
    const std::string& payer_account_id_hex,
    const std::vector<std::string>& shard_program_account_ids_hex
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

    FfiBytes32 program_account_id{};
    if (!hexToBytes32(program_id_hex, &program_account_id)) {
        fprintf(stderr, "send_generic_public_transaction: invalid program_id_hex\n");
        return transferResultToJson(nullptr, std::string("send_generic_public_transaction: invalid program_id_hex"));
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

        WalletFfiError error = wallet_ffi_resolve_public_account(id, signing_requirements[i], &acc_identity);
        if (error != SUCCESS) {
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
            identities_resolved, shard_program_account_ids_hex, &program_account_id, mentions, mentions_error
        )) {
        fprintf(stderr, "send_generic_public_transaction: %s\n", mentions_error.c_str());
        free_identities();
        return transferResultToJson(nullptr, "send_generic_public_transaction: " + mentions_error);
    }

    FfiTransactionResult result{};

    const WalletFfiError error = wallet_ffi_send_generic_public_transaction(
        walletHandle,
        mentions.data(),
        static_cast<uintptr_t>(mentions.size()),
        instruction.data(),
        static_cast<uintptr_t>(instruction.size()),
        program_account_id,
        payer_ptr,
        &result
    );

    free_identities();

    if (error != SUCCESS) {
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
    const std::vector<uint8_t>& instruction,
    const std::vector<uint8_t>& program_elf,
    const std::string& program_kind_json,
    const std::vector<std::vector<uint8_t>>& program_dependencies,
    const std::vector<std::string>& dependency_kinds_json,
    const std::vector<std::string>& shard_program_account_ids_hex
) {
    if (dependency_kinds_json.size() != program_dependencies.size()) {
        fprintf(
            stderr, "send_generic_private_transaction: dependency_kinds_json size must match program_dependencies\n"
        );
        return transferResultToJson(
            nullptr, "send_generic_private_transaction: dependency_kinds_json size must match program_dependencies"
        );
    }

    ParsedProgramKind root{};
    if (!jsonToProgramKind(program_kind_json, &root)) {
        fprintf(stderr, "send_generic_private_transaction: invalid program_kind_json\n");
        return transferResultToJson(nullptr, "send_generic_private_transaction: invalid program_kind_json");
    }
    // Native execution supplies no bytecode, so it can only be dispatched at a known address.
    if (program_elf.empty() && root.kind != FfiProgramKind::PROGRAM_DISCLOSED) {
        fprintf(stderr, "send_generic_private_transaction: an empty program_elf requires a disclosed kind\n");
        return transferResultToJson(
            nullptr, "send_generic_private_transaction: an empty program_elf requires a disclosed kind"
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
            fprintf(stderr, "send_generic_private_transaction: invalid dependency_kinds_json[%zu]\n", i);
            return transferResultToJson(
                nullptr, "send_generic_private_transaction: invalid dependency_kinds_json[" + std::to_string(i) + "]"
            );
        }
        if (dependency_kinds[i].kind != FfiProgramKind::PROGRAM_SHADOW &&
            memcmp(dependency_kinds[i].account_id.data, self_account_id.data, 32) == 0) {
            fprintf(stderr, "send_generic_private_transaction: dependency %zu has the root's account_id\n", i);
            return transferResultToJson(
                nullptr,
                "send_generic_private_transaction: dependency " + std::to_string(i) + " has the root's account_id"
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
        const bool is_shadow = parsed.kind == FfiProgramKind::PROGRAM_SHADOW;
        programs.push_back(
            toFfiDependency(program_dependencies[i], parsed, is_shadow ? never_self : parsed.account_id)
        );
    }

    FfiProgramWithDependencies program_with_dependencies{};
    program_with_dependencies.self_account_id = self_account_id;
    program_with_dependencies.programs = programs.data();
    program_with_dependencies.programs_size = static_cast<uintptr_t>(programs.size());

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
            fprintf(stderr, "wallet_ffi_resolve_private_account: invalid account_id_hex");
            free_identities();
            return transferResultToJson(
                nullptr, std::string("wallet_ffi_resolve_private_account: invalid account_id_hex")
            );
        }

        WalletFfiError error = wallet_ffi_resolve_private_account(walletHandle, id, &acc_identity);
        if (error != SUCCESS) {
            fprintf(stderr, "wallet_ffi_resolve_private_account failed for index %d: wallet FFI error %d\n", i, error);
            free_identities();
            return transferResultToJson(
                nullptr, std::string("wallet_ffi_resolve_private_account: wallet FFI error ") + std::to_string(error)
            );
        }
        identities_resolved.push_back(acc_identity);
    }

    std::vector<FfiAccountMention> mentions;
    std::string mentions_error;
    if (!buildAccountMentions(
            identities_resolved,
            shard_program_account_ids_hex,
            root.has_account_id ? &root.account_id : nullptr,
            mentions,
            mentions_error
        )) {
        fprintf(stderr, "send_generic_private_transaction: %s\n", mentions_error.c_str());
        free_identities();
        return transferResultToJson(nullptr, "send_generic_private_transaction: " + mentions_error);
    }

    FfiTransactionResult result{};

    const WalletFfiError error = wallet_ffi_send_generic_private_transaction(
        walletHandle,
        mentions.data(),
        static_cast<uintptr_t>(mentions.size()),
        instruction.data(),
        static_cast<uintptr_t>(instruction.size()),
        &program_with_dependencies,
        &result
    );

    free_identities();

    if (error != SUCCESS) {
        fprintf(stderr, "send_generic_private_transaction: wallet FFI error %d\n", error);
        return transferResultToJson(
            nullptr, std::string("send_generic_private_transaction: wallet FFI error ") + std::to_string(error)
        );
    }
    std::string resultJson = genericTransactionResultToJson(&result, std::string());
    wallet_ffi_free_transaction_result(&result);
    return resultJson;
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
    const WalletFfiError error = wallet_ffi_program_loader_deploy(
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

    if (error != SUCCESS) {
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

    const WalletFfiError error = wallet_ffi_poll_transaction_status(walletHandle, tx_hash, &is_found);

    if (error != SUCCESS) {
        fprintf(stderr, "poll_transaction_status: wallet FFI error %d\n", error);
        return false;
    }

    return is_found;
}

// === Wallet Lifecycle ===

std::string LEZCoreModule::create_new(
    const std::string& config_path,
    const std::string& storage_path,
    const std::string& statistics_path,
    const std::string& password
) {
    if (walletHandle) {
        fprintf(stderr, "create_new: wallet is already open\n");
        return {};
    }

    FfiCreateWalletOutput create_output =
        wallet_ffi_create_new(config_path.c_str(), storage_path.c_str(), statistics_path.c_str(), password.c_str());
    if (!create_output.wallet) {
        fprintf(stderr, "create_new: wallet_ffi_create_new returned null\n");
        return {};
    }

    walletHandle = create_output.wallet;
    std::string mnemonic(create_output.mnemonic);

    wallet_ffi_free_string(create_output.mnemonic);

    return mnemonic;
}

int64_t LEZCoreModule::restore_storage(const std::string& mnemonic, const std::string password, uint32_t depth) {
    const WalletFfiError error = wallet_ffi_restore_data(walletHandle, mnemonic.c_str(), password.c_str(), depth);
    if (error != SUCCESS) {
        fprintf(stderr, "restore_storage: wallet FFI error %d\n", error);
        return error;
    }

    return SUCCESS;
}

int64_t LEZCoreModule::open(
    const std::string& config_path,
    const std::string& storage_path,
    const std::string& statistics_path
) {
    if (walletHandle) {
        fprintf(stderr, "open: wallet is already open\n");
        return INTERNAL_ERROR;
    }

    walletHandle = wallet_ffi_open(config_path.c_str(), storage_path.c_str(), statistics_path.c_str());
    if (!walletHandle) {
        fprintf(stderr, "open: wallet_ffi_open returned null\n");
        return INTERNAL_ERROR;
    }

    return SUCCESS;
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
    wallet_ffi_free_string(addr);
    return value;
}

// === Labels ===

bool LEZCoreModule::check_label_available(const std::string& label) {
    const char* label_c = label.c_str();

    LabelAvailability label_check = wallet_ffi_check_label_available(walletHandle, label_c);

    if (label_check.error != SUCCESS) {
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
        return WalletFfiError::INVALID_ACCOUNT_ID;
    }

    FfiAccountIdWithPrivacy acc_id_with_privacy = {id, is_private};

    WalletFfiError error = wallet_ffi_add_label(walletHandle, label_c, acc_id_with_privacy);
    if (error != SUCCESS) {
        fprintf(stderr, "wallet_ffi_add_label failed : wallet FFI error %d\n", error);
    }

    return SUCCESS;
}

std::string LEZCoreModule::resolve_label(const std::string& label) {
    const char* label_c = label.c_str();

    AccountIdResolvedFromLabel acc_id_res = wallet_ffi_resolve_label(walletHandle, label_c);

    if (acc_id_res.error != SUCCESS) {
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

    if (label_list.error != SUCCESS) {
        fprintf(stderr, "wallet_ffi_get_all_labels_for_account failed : wallet FFI error %d\n", label_list.error);
        return {};
    }

    std::vector<std::string> result;
    result.reserve(label_list.labels_size);

    for (uintptr_t i = 0; i < label_list.labels_size; ++i) {
        result.emplace_back(label_list.labels_data[i]);
    }

    WalletFfiError err = wallet_ffi_free_label_list(&label_list);

    if (err != SUCCESS) {
        fprintf(stderr, "wallet_ffi_free_label_list failed : wallet FFI error %d\n", err);
        return {};
    }

    return result;
}
