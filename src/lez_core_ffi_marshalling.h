#pragma once

#include <core_ffi.h>

#include <nlohmann/json.hpp>
#include <string>

// FFI marshalling helpers
//
// Bridge the raw C structs returned by the core FFI (core_ffi.h) to the
// compact JSON the LEZ explorer's Block/Transaction/Account models consume, and
// parse the std::string inputs back into FFI types. Kept in their own
// translation unit so lez_core_module_impl.cpp stays focused on the query
// flow and the JSON data model lives in one place.
//
// This header pulls in the FFI types + nlohmann::json, so it is included only
// from .cpp files — NOT from lez_core_module_impl.h, whose Qt-free,
// FFI-free shape the universal codegen parses.
//
// These never take ownership of FFI memory: the caller frees it with the
// matching primitives_free_ffi_* function AFTER marshalling.
//
// Large 64-bit values (ids, timestamps, validity windows) and 128-bit values
// (balances, nonces) are emitted as decimal STRINGS to avoid the double-
// precision loss of JSON numbers; counts/sizes are emitted as numbers.
namespace marshalling {

    namespace JsonKeys {
        constexpr auto TxHash = "tx_hash";
        constexpr auto Success = "success";
        constexpr auto Error = "error";
        constexpr auto Nonce = "nonce";
        constexpr auto ActorStates = "actor_states";
        constexpr auto Program = "program";
        constexpr auto Data = "data";
        constexpr auto NullifierPublicKey = "nullifier_public_key";
        constexpr auto ViewingPublicKey = "viewing_public_key";
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
        constexpr auto KindPrivateOwned = "private_owned";
        constexpr auto KindPublic = "public";
        constexpr auto KindPublicNoSign = "public_no_sign";
        constexpr auto KindPrivateForeign = "private_foreign";
    } // namespace JsonKeys

    // Lower-case hex of `length` raw bytes (32-byte hashes/ids/keys).
    std::string bytesToHex(const uint8_t* data, size_t length);

    // FfiU128 is a 16-byte little-endian integer (balances, nonces); rendered
    // as a decimal string.
    std::string u128LeToDecimal(const uint8_t data[16]);

    // 64-bit value as a decimal string.
    std::string u64ToString(uint64_t v);

    // Parse a hex string (optionally 0x-prefixed) into a fixed 32-byte buffer.
    // Returns false unless it decodes to exactly 32 bytes.
    bool hexToBytes32(const std::string& hex, FfiBytes32* out);

    // True iff `s` is exactly `num_chars` hex digits (no 0x prefix, no whitespace).
    // For validating fixed-width hex identifiers (e.g. a 64-char channel id) before
    // trusting them as-is, such as when composing a filesystem path.
    bool isHex(const std::string& s, size_t num_chars);

    // Base58 (plain Bitcoin alphabet, no checksum) of `length` raw bytes. This is
    // the canonical string form of an LEZ *account id* — it matches lee::AccountId
    // Display, wallet_ffi's account_id_to_base58, and the wallet UI's Base58.js.
    // Hashes/tx ids/program ids stay hex; only account ids are Base58.
    std::string bytes32ToBase58(const uint8_t* data, size_t length);

    // Parse an account id string into a fixed 32-byte buffer, accepting EITHER
    // Base58 (canonical) or 64-char hex (optionally 0x-prefixed). Base58 is tried
    // first; since a 32-byte value's Base58 is ~44 chars, a 64-hex string fails the
    // 32-byte check and falls through to hex. Returns false unless it resolves to
    // exactly 32 bytes.
    bool accountStrToBytes32(const std::string& account_id, FfiBytes32* out);

    nlohmann::json ffiTransactionToJson(const FfiTransaction& tx);
    nlohmann::json ffiBlockToJson(const FfiBlock& block);

    // Compact serialization (no spaces/newlines) of an object or array.
    std::string jsonToCompactString(const nlohmann::json& j);

    // Balance from wallet_ffi_get_balance is 16 bytes little-endian (u128). Convert to decimal string for UI.
    // Requires __uint128_t (GCC/Clang on 64-bit).
    std::string balanceLe16ToDecimalString(const uint8_t* data);

    bool hexToBytes(const std::string& hex, std::vector<uint8_t>& output_bytes, int expectedLength);
    bool hexToU128(const std::string& hex, uint8_t (*output)[16]);
    std::string bytes32ToHex(const FfiBytes32& bytes);

    // Builds JSON { success, tx_hash, error } for both success (result + empty error) and failure (nullptr +
    // errorMessage).
    std::string transferResultToJson(const FfiTransferResult* result, const std::string& errorMessage);
    // Builds JSON { success, tx_hash, secrets, error } for both success (result + empty error) and failure (nullptr +
    // errorMessage) in case of generic transaction.
    std::string genericTransactionResultToJson(const FfiTransactionResult* result, const std::string& errorMessage);
    nlohmann::json ffiAccountToJson(const FfiAccount& account);
    nlohmann::json ffiAccountListEntryToJson(const FfiAccountListEntry& entry);
    std::string ffiPrivateAccountKeysToJson(const FfiPrivateAccountKeys& keys);
    bool jsonToFfiPrivateAccountKeys(const std::string& json, FfiPrivateAccountKeys* output_keys);
    // Parses a JSON array of 32-byte hex strings into a contiguous byte buffer of siblings.
    // Returns true on success, with out_len set to the number of siblings and out_bytes sized to out_len*32.
    bool jsonArrayHexToSiblings32(const std::string& json_array_str, std::vector<uint8_t>& out_bytes, uintptr_t& out_len);

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

    bool jsonToProgramKind(const std::string& json, ParsedProgramKind* out);
} // namespace marshalling