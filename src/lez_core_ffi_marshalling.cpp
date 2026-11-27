#include "lez_core_ffi_marshalling.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

namespace marshalling {

    namespace {
        // Single hex nibble -> 0..15, or -1 if not a hex digit.
        int hexNibble(char c) {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        }

        // Plain Bitcoin Base58 alphabet (no checksum, no version byte). Must stay
        // byte-for-byte identical to the `base58` crate (lee::AccountId) and the
        // wallet UI's Base58.js so account-id strings round-trip across the stack.
        constexpr char kBase58Alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        // Position of `c` in the Base58 alphabet, or -1 if not a Base58 char.
        int base58Index(char c) {
            for (int i = 0; i < 58; ++i) {
                if (kBase58Alphabet[i] == c)
                    return i;
            }
            return -1;
        }

        // Decode a Base58 string (whitespace-trimmed) into raw bytes. Returns
        // false on any character outside the alphabet. Big-integer base 58 -> 256,
        // leading '1's map to leading zero bytes. Mirrors Base58.js::decode.
        bool base58Decode(const std::string& s, std::vector<uint8_t>* out) {
            size_t begin = 0;
            size_t end = s.size();
            while (begin < end && std::isspace(static_cast<unsigned char>(s[begin])))
                ++begin;
            while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])))
                --end;
            if (begin == end) {
                return false;
            }

            size_t leadingZeros = 0;
            for (size_t i = begin; i < end && s[i] == '1'; ++i) {
                ++leadingZeros;
            }

            std::vector<uint8_t> digits; // base-256, least-significant first
            for (size_t i = begin; i < end; ++i) {
                const int idx = base58Index(s[i]);
                if (idx < 0) {
                    return false;
                }
                int carry = idx;
                for (size_t j = 0; j < digits.size(); ++j) {
                    carry += digits[j] * 58;
                    digits[j] = static_cast<uint8_t>(carry & 0xFF);
                    carry >>= 8;
                }
                while (carry > 0) {
                    digits.push_back(static_cast<uint8_t>(carry & 0xFF));
                    carry >>= 8;
                }
            }

            out->assign(leadingZeros, 0);
            for (size_t i = digits.size(); i-- > 0;) {
                out->push_back(digits[i]);
            }
            return true;
        }
    } // namespace

    // Lower-case hex of `length` raw bytes (used for 32-byte hashes/ids/keys).
    std::string bytesToHex(const uint8_t* data, const size_t length) {
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.resize(length * 2);
        for (size_t i = 0; i < length; ++i) {
            out[2 * i] = digits[(data[i] >> 4) & 0xF];
            out[2 * i + 1] = digits[data[i] & 0xF];
        }
        return out;
    }

    // FfiU128 is a 16-byte little-endian integer (balances, nonces). C++ has no
    // native u128, so build the decimal string via __uint128_t (GCC/Clang, 64-bit).
    std::string u128LeToDecimal(const uint8_t data[16]) {
#if defined(__SIZEOF_INT128__) && __SIZEOF_INT128__ >= 16
        __uint128_t v = 0;
        for (int i = 0; i < 16; ++i) {
            v |= static_cast<__uint128_t>(data[i]) << (i * 8);
        }
        if (v == 0) {
            return "0";
        }
        char buf[40];
        int n = 0;
        while (v) {
            buf[n++] = static_cast<char>('0' + static_cast<int>(v % 10));
            v /= 10;
        }
        std::reverse(buf, buf + n);
        return std::string(buf, n);
#else
#error "u128LeToDecimal requires __uint128_t; build with GCC or Clang on 64-bit"
#endif
    }

    // 64-bit values are emitted as decimal STRINGS, not JSON numbers: JSON
    // numbers are doubles in many parsers and silently lose precision above 2^53.
    std::string u64ToString(uint64_t v) {
        return std::to_string(v);
    }

    // Parse a hex string (optionally 0x-prefixed) into a fixed 32-byte FfiBytes32.
    // Returns false unless it decodes to exactly 32 bytes.
    bool hexToBytes32(const std::string& hex, FfiBytes32* out) {
        size_t begin = 0;
        size_t end = hex.size();
        while (begin < end && std::isspace(static_cast<unsigned char>(hex[begin])))
            ++begin;
        while (end > begin && std::isspace(static_cast<unsigned char>(hex[end - 1])))
            --end;

        if (end - begin >= 2 && hex[begin] == '0' && (hex[begin + 1] == 'x' || hex[begin + 1] == 'X')) {
            begin += 2;
        }

        if (end - begin != 64) {
            return false;
        }

        for (size_t i = 0; i < 32; ++i) {
            const int hi = hexNibble(hex[begin + 2 * i]);
            const int lo = hexNibble(hex[begin + 2 * i + 1]);
            if (hi < 0 || lo < 0) {
                return false;
            }
            out->data[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    // True iff `s` is exactly `num_chars` hex digits (no prefix/whitespace).
    bool isHex(const std::string& s, const size_t num_chars) {
        if (s.size() != num_chars) {
            return false;
        }
        for (const char c : s) {
            if (hexNibble(c) < 0) {
                return false;
            }
        }
        return true;
    }

    // Base58-encode `length` raw bytes (plain Bitcoin alphabet). Big-integer
    // base 256 -> 58, leading zero bytes map to leading '1's. Mirrors
    // Base58.js::encode so account ids match the wallet UI and canonical LEZ.
    std::string bytes32ToBase58(const uint8_t* data, const size_t length) {
        size_t leadingZeros = 0;
        while (leadingZeros < length && data[leadingZeros] == 0) {
            ++leadingZeros;
        }

        std::vector<uint8_t> digits; // base-58, least-significant first
        for (size_t i = 0; i < length; ++i) {
            int carry = data[i];
            for (size_t j = 0; j < digits.size(); ++j) {
                carry += digits[j] * 256;
                digits[j] = static_cast<uint8_t>(carry % 58);
                carry /= 58;
            }
            while (carry > 0) {
                digits.push_back(static_cast<uint8_t>(carry % 58));
                carry /= 58;
            }
        }

        std::string out(leadingZeros, '1');
        for (size_t i = digits.size(); i-- > 0;) {
            out += kBase58Alphabet[digits[i]];
        }
        return out;
    }

    // Accept an account id as Base58 (canonical) or 64-char hex. Base58 first:
    // a real 32-byte account is ~44 Base58 chars, so a 64-hex string either hits a
    // non-Base58 char (e.g. '0') or decodes to the wrong length and falls through.
    bool accountStrToBytes32(const std::string& account_id, FfiBytes32* out) {
        std::vector<uint8_t> bytes;
        if (base58Decode(account_id, &bytes) && bytes.size() == 32) {
            std::memcpy(out->data, bytes.data(), 32);
            return true;
        }
        return hexToBytes32(account_id, out);
    }

    namespace {
        nlohmann::json declaredActorsToJson(const FfiDeclaredActorList& actors, const FfiNonceList& nonces) {
            nlohmann::json accounts = nlohmann::json::array();
            for (uintptr_t i = 0; i < actors.len; ++i) {
                const FfiDeclaredActor& declared = actors.entries[i];
                nlohmann::json ref;
                ref["account_id"] = bytes32ToBase58(declared.actor.account_id.data, 32);
                ref["program_account_id"] = bytes32ToBase58(declared.actor.program_account_id.data, 32);
                ref["signer"] = declared.signer;
                // Only the signing accounts have one; the list is keyed by account, not parallel.
                ref["nonce"] = nullptr;
                for (uintptr_t n = 0; n < nonces.len; ++n) {
                    if (std::memcmp(nonces.entries[n].account_id.data, declared.actor.account_id.data, 32) == 0) {
                        ref["nonce"] = u128LeToDecimal(nonces.entries[n].nonce.data);
                        break;
                    }
                }
                accounts.push_back(ref);
            }
            return accounts;
        }

        // Declared fee (payer + caps), not the amount charged; that is in the block's receipt.
        nlohmann::json feeDeclarationToJson(const FfiFeeDeclaration& fee) {
            nlohmann::json obj;
            obj["payer"] = bytes32ToBase58(fee.payer.data, 32);
            obj["gas_limit"] = u64ToString(fee.gas_limit);
            obj["tip"] = u64ToString(fee.tip);
            obj["max_fee"] = u128LeToDecimal(fee.max_fee.data);
            return obj;
        }

        nlohmann::json receiptToJson(const FfiTransactionReceipt& receipt) {
            nlohmann::json obj;
            obj["success"] = receipt.success;
            obj["gas_exec"] = u64ToString(receipt.fee.gas_exec);
            obj["gas_stor"] = u64ToString(receipt.fee.gas_stor);
            obj["fee_base"] = u128LeToDecimal(receipt.fee.fee_base.data);
            obj["tip"] = u128LeToDecimal(receipt.fee.tip.data);
            obj["refund"] = u128LeToDecimal(receipt.fee.refund.data);
            return obj;
        }
    } // namespace

    nlohmann::json ffiTransactionToJson(const FfiTransaction& tx) {
        nlohmann::json obj;

        switch (tx.kind) {
        case FfiTransactionKind_Public: {
            const FfiPublicTransactionBody* body = tx.body.public_body;
            if (!body) {
                break;
            }
            obj["type"] = "Public";
            obj["hash"] = bytesToHex(body->hash.data, 32);
            obj["program_account_id"] = bytes32ToBase58(body->message.root.to.program_account_id.data, 32);

            obj["accounts"] = declaredActorsToJson(body->message.public_context.actors, body->message.nonces);

            // Raw message bytes as hex.
            const FfiMessageDataList& messsage = body->message.root.message;
            obj["message"] = bytesToHex(messsage.entries, messsage.len);
            obj["signature_count"] = static_cast<int>(body->witness_set.len);

            // Null for fee-exempt/system transactions.
            obj["fee"] = body->message.has_fee ? feeDeclarationToJson(body->message.fee) : nlohmann::json(nullptr);
            break;
        }
        case FfiTransactionKind_Private: {
            const FfiPrivateTransactionBody* body = tx.body.private_body;
            if (!body) {
                break;
            }
            obj["type"] = "PrivacyPreserving";
            obj["hash"] = bytesToHex(body->hash.data, 32);

            obj["accounts"] = declaredActorsToJson(body->message.public_context.actors, body->message.nonces);

            // Set when a public signer pays; null when the fee is paid inside the proof.
            obj["fee"] = body->message.has_fee ? feeDeclarationToJson(body->message.fee) : nlohmann::json(nullptr);
            // Paid inside the proof: the amount and payer stay private.
            if (body->message.has_proven_fee) {
                const FfiProvenFee& proven = body->message.proven_fee;
                nlohmann::json provenObj;
                provenObj["tip"] = u64ToString(proven.tip);
                provenObj["refund_to"] = proven.has_refund_to
                                             ? nlohmann::json(bytes32ToBase58(proven.refund_to.data, 32))
                                             : nlohmann::json(nullptr);
                provenObj["has_fallback"] = proven.has_fallback;
                obj["proven_fee"] = provenObj;
            } else {
                obj["proven_fee"] = nullptr;
            }

            // Each private action bundles nullifier + root + commitment +
            // encrypted post-state, so the former per-list counts collapse
            // into this single count.
            obj["private_actions_count"] = static_cast<int>(body->message.private_actions.len);
            obj["validity_window_start"] = u64ToString(body->message.block_validity_window[0]);
            obj["validity_window_end"] = u64ToString(body->message.block_validity_window[1]);
            obj["signature_count"] = static_cast<int>(body->witness_set.len);
            obj["proof_size"] = static_cast<int>(body->proof.len);
            break;
        }
        }

        return obj;
    }

    namespace {
        std::string bedrockStatusToString(FfiBedrockStatus status) {
            switch (status) {
            case FfiBedrockStatus_Safe:
                return "Safe";
            case FfiBedrockStatus_Finalized:
                return "Finalized";
            case FfiBedrockStatus_Pending:
            default:
                return "Pending";
            }
        }
    } // namespace

    nlohmann::json ffiBlockToJson(const FfiBlock& block) {
        nlohmann::json obj;
        obj["block_id"] = u64ToString(block.header.block_id);
        obj["hash"] = bytesToHex(block.header.hash.data, 32);
        obj["prev_block_hash"] = bytesToHex(block.header.prev_block_hash.data, 32);
        obj["timestamp"] = u64ToString(block.header.timestamp);
        obj["bedrock_status"] = bedrockStatusToString(block.bedrock_status);

        nlohmann::json transactions = nlohmann::json::array();
        for (uintptr_t i = 0; i < block.body.len; ++i) {
            nlohmann::json tx = ffiTransactionToJson(block.body.entries[i]);
            tx["receipt"] =
                i < block.receipts.len ? receiptToJson(block.receipts.entries[i]) : nlohmann::json(nullptr);
            transactions.push_back(tx);
        }
        obj["transactions"] = transactions;
        return obj;
    }

    nlohmann::json executorStatusToJson(const ExecutorStatusResult& status) {
        const auto optional = [](bool has, uint64_t value) {
            return has ? nlohmann::json(u64ToString(value)) : nlohmann::json(nullptr);
        };
        nlohmann::json obj;
        obj["state"] = status.state == FfiExecutorState_Online ? "Online" : "Bootstrapping";
        obj["height"] = optional(status.has_height, status.height);
        obj["target_slot"] = optional(status.has_target_slot, status.target_slot);
        obj["replayed_up_to_slot"] = optional(status.has_replayed_up_to_slot, status.replayed_up_to_slot);
        obj["is_our_turn"] = status.is_our_turn;
        return obj;
    }

    std::string jsonToCompactString(const nlohmann::json& j) {
        return j.dump();
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

    nlohmann::json feeStateToJson(const FfiFeeState& state) {
        nlohmann::json obj;
        obj["height"] = u64ToString(state.height);
        obj["base_fee_exec"] = u64ToString(state.base_fee_exec);
        obj["base_fee_stor"] = u64ToString(state.base_fee_stor);
        obj["next_base_fee_exec_floor"] = u64ToString(state.next_base_fee_exec_floor);
        obj["next_base_fee_exec_ceiling"] = u64ToString(state.next_base_fee_exec_ceiling);
        obj["next_base_fee_stor_floor"] = u64ToString(state.next_base_fee_stor_floor);
        obj["next_base_fee_stor_ceiling"] = u64ToString(state.next_base_fee_stor_ceiling);
        obj["max_gas_exec"] = u64ToString(state.max_gas_exec);
        obj["max_gas_stor"] = u64ToString(state.max_gas_stor);
        return obj;
    }

    namespace {
        // Decimal string or JSON unsigned number, up to `max`.
        bool jsonToUint(const nlohmann::json& value, const __uint128_t max, __uint128_t* out) {
            if (value.is_number_unsigned()) {
                *out = value.get<uint64_t>();
                return *out <= max;
            }
            if (!value.is_string()) {
                return false;
            }
            const std::string digits = value.get<std::string>();
            if (digits.empty()) {
                return false;
            }
            __uint128_t acc = 0;
            for (const char c : digits) {
                if (c < '0' || c > '9') {
                    return false;
                }
                const __uint128_t digit = static_cast<__uint128_t>(c - '0');
                if (acc > (max - digit) / 10) {
                    return false;
                }
                acc = acc * 10 + digit;
            }
            *out = acc;
            return true;
        }

        bool jsonToU64(const nlohmann::json& value, uint64_t* out) {
            __uint128_t wide = 0;
            if (!jsonToUint(value, UINT64_MAX, &wide)) {
                return false;
            }
            *out = static_cast<uint64_t>(wide);
            return true;
        }

        bool jsonToU128Le(const nlohmann::json& value, FfiU128* out) {
            __uint128_t wide = 0;
            if (!jsonToUint(value, ~static_cast<__uint128_t>(0), &wide)) {
                return false;
            }
            for (int i = 0; i < 16; ++i) {
                out->data[i] = static_cast<uint8_t>(wide >> (i * 8));
            }
            return true;
        }

        bool jsonToAccountId(const nlohmann::json& value, FfiBytes32* out) {
            return value.is_string() && accountStrToBytes32(value.get<std::string>(), out);
        }

        nlohmann::json declaredFeeToJson(const FfiDeclaredFee& fee) {
            switch (fee.kind) {
            case FfiFeeKind_Public: {
                nlohmann::json obj = feeDeclarationToJson(fee.public_fee);
                obj[JsonKeys::Kind] = "public";
                return obj;
            }
            case FfiFeeKind_Private: {
                nlohmann::json obj;
                obj[JsonKeys::Kind] = "private";
                obj["payer"] = bytes32ToBase58(fee.private_fee.payer.data, 32);
                obj["reserve"] = u128LeToDecimal(fee.private_fee.reserve.data);
                obj["tip"] = u64ToString(fee.private_fee.tip);
                obj["refund_to"] = fee.private_fee.has_refund_to
                                       ? nlohmann::json(bytes32ToBase58(fee.private_fee.refund_to.data, 32))
                                       : nlohmann::json(nullptr);
                return obj;
            }
            case FfiFeeKind_None:
            default:
                return nullptr;
            }
        }

        // The fields marked private are zero for a public send, and the other way round.
        nlohmann::json dryRunReportToJson(const FfiDryRunReport& report) {
            nlohmann::json obj;
            obj["fee_state"] = feeStateToJson(report.fee_state);
            obj["cycles"] = u64ToString(report.cycles);
            obj["fee_at_head"] = u128LeToDecimal(report.fee_at_head.data);
            obj["reserve_at_head"] = u128LeToDecimal(report.reserve_at_head.data);
            obj["wire_bytes"] = u64ToString(report.wire_bytes);
            obj["revert_reason"] =
                report.revert_reason ? nlohmann::json(std::string(report.revert_reason)) : nlohmann::json(nullptr);
            obj["headroom_blocks"] = u64ToString(report.headroom_blocks);
            obj["exec_ceiling"] = u64ToString(report.exec_ceiling);
            obj["stor_ceiling"] = u64ToString(report.stor_ceiling);
            obj["headroom_reserve"] = u128LeToDecimal(report.headroom_reserve.data);
            obj["claims"] = u64ToString(report.claims);
            obj["swept"] = u128LeToDecimal(report.swept.data);
            return obj;
        }

        // `result` is null on the failure path.
        template <typename Result> void addFeeOutcome(nlohmann::json& obj, const Result* result) {
            const bool isDryRun = result && result->is_dry_run;
            obj["is_dry_run"] = isDryRun;
            obj["dry_run"] = isDryRun ? dryRunReportToJson(result->dry_run) : nlohmann::json(nullptr);
            obj["fee"] = result ? declaredFeeToJson(result->fee) : nlohmann::json(nullptr);
        }
    } // namespace

    bool jsonToFeeParams(
        const std::string& json,
        FfiFeeParams* out,
        bool* out_allow_revert,
        std::string* out_error
    ) {
        *out = FfiFeeParams{};
        *out_allow_revert = false;

        const nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) {
            *out_error = "fee_params_json must be a JSON object";
            return false;
        }

        for (const auto& [key, value] : doc.items()) {
            bool ok = false;
            if (key == "gas_limit") {
                ok = out->has_gas_limit = jsonToU64(value, &out->gas_limit);
            } else if (key == "max_fee") {
                ok = out->has_max_fee = jsonToU128Le(value, &out->max_fee);
            } else if (key == "tip") {
                ok = jsonToU64(value, &out->tip);
            } else if (key == "headroom_blocks") {
                ok = out->has_headroom_blocks = jsonToU64(value, &out->headroom_blocks);
            } else if (key == "payer") {
                ok = out->has_payer = jsonToAccountId(value, &out->payer);
            } else if (key == "refund_to") {
                ok = out->has_refund_to = jsonToAccountId(value, &out->refund_to);
            } else if (key == "payer_is_public") {
                ok = value.is_boolean();
                out->payer_is_public = ok && value.get<bool>();
            } else if (key == "allow_revert") {
                ok = value.is_boolean();
                *out_allow_revert = ok && value.get<bool>();
            } else {
                *out_error = "unknown fee_params_json key \"" + key + "\"";
                return false;
            }
            if (!ok) {
                *out_error = "invalid fee_params_json \"" + key + "\"";
                return false;
            }
        }
        return true;
    }

    // Builds JSON { success, tx_hash, error } for both success (result + empty error) and failure (nullptr +
    // errorMessage).
    std::string transferResultToJson(const FfiTransferResult* result, const std::string& errorMessage) {
        nlohmann::json obj = nlohmann::json::object();
        const bool isError = !errorMessage.empty();
        obj[JsonKeys::Success] = !isError && result && result->success;
        obj[JsonKeys::TxHash] = (!isError && result && result->tx_hash) ? std::string(result->tx_hash) : std::string();
        addFeeOutcome(obj, isError ? nullptr : result);
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
        addFeeOutcome(obj, isError ? nullptr : result);
        obj[JsonKeys::Error] = errorMessage;
        return obj.dump();
    }

    // Builds JSON { nonce, actor_states: [{ program, data }] }.
    nlohmann::json ffiAccountToJson(const FfiAccount& account) {
        nlohmann::json obj = nlohmann::json::object();
        obj[JsonKeys::Nonce] = u128LeToDecimal(account.nonce.data);
        nlohmann::json actor_states = nlohmann::json::array();
        for (uintptr_t i = 0; account.actor_states && i < account.actor_states_len; ++i) {
            const FfiActorState& actor_state = account.actor_states[i];
            nlohmann::json actorStateObj = nlohmann::json::object();
            actorStateObj[JsonKeys::Program] = bytes32ToHex(actor_state.program);
            actorStateObj[JsonKeys::Data] =
                (actor_state.data && actor_state.data_len > 0) ? bytesToHex(actor_state.data, actor_state.data_len) : std::string();
            actor_states.push_back(actorStateObj);
        }
        obj[JsonKeys::ActorStates] = actor_states;
        return obj;
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
        if (keys.viewing_public_key.entries && keys.viewing_public_key.len > 0) {
            obj[JsonKeys::ViewingPublicKey] = bytesToHex(keys.viewing_public_key.entries, keys.viewing_public_key.len);
        } else {
            obj[JsonKeys::ViewingPublicKey] = "";
        }
        return obj.dump();
    }

    bool jsonToFfiPrivateAccountKeys(const std::string& json, FfiPrivateAccountKeys* output_keys) {
        if (!output_keys)
            return false;

        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object())
            return false;

        // Nullifier public key is mandatory: a missing/wrong-typed value must not fall back to zero.
        const auto npkIt = doc.find(JsonKeys::NullifierPublicKey);
        if (npkIt == doc.end() || !npkIt->is_string())
            return false;

        FfiBytes32 nullifierPublicKey{};
        if (!hexToBytes32(npkIt->get<std::string>(), &nullifierPublicKey))
            return false;

        // Viewing public key is optional: absent means empty (nullptr, 0).
        std::vector<uint8_t> viewingPublicKey;
        const auto vpkIt = doc.find(JsonKeys::ViewingPublicKey);
        if (vpkIt != doc.end()) {
            if (!vpkIt->is_string())
                return false;
            if (!hexToBytes(vpkIt->get<std::string>(), viewingPublicKey))
                return false;
        }

        const uint8_t* vpkData = viewingPublicKey.empty() ? nullptr : viewingPublicKey.data();

        const FfiOperationError err = wallet_ffi_make_private_account_keys_from_raw(
            nullifierPublicKey,
            vpkData,
            viewingPublicKey.size(),
            output_keys);

        return err == FfiOperationError_Success;
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

    bool jsonToProgramKind(const std::string& json, ParsedProgramKind* out) {
        nlohmann::json doc = nlohmann::json::parse(json, nullptr, false);
        if (doc.is_discarded() || !doc.is_object())
            return false;
        if (!doc.contains(JsonKeys::Kind) || !doc[JsonKeys::Kind].is_string())
            return false;

        const std::string kindStr = doc[JsonKeys::Kind].get<std::string>();
        if (kindStr == JsonKeys::KindDisclosed)
            out->kind = FfiProgramKind::FfiProgramKind_ProgramDisclosed;
        else if (kindStr == JsonKeys::KindShadow)
            out->kind = FfiProgramKind::FfiProgramKind_ProgramShadow;
        else if (kindStr == JsonKeys::KindUndisclosed)
            out->kind = FfiProgramKind::FfiProgramKind_ProgramUndisclosed;
        else
            return false;

        if (doc.contains(JsonKeys::AccountId)) {
            if (!doc[JsonKeys::AccountId].is_string())
                return false;
            if (!hexToBytes32(doc[JsonKeys::AccountId].get<std::string>(), &out->account_id))
                return false;
            out->has_account_id = true;
        }

        if (out->kind == FfiProgramKind::FfiProgramKind_ProgramShadow)
            return true;
        if (!out->has_account_id)
            return false;
        if (out->kind == FfiProgramKind::FfiProgramKind_ProgramDisclosed)
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

} // namespace marshalling