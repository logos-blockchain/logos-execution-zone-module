// Unit tests for LEZCoreModule.
// All wallet_ffi C functions are mocked at link time via mock_wallet_ffi.cpp.

#include "lez_core_module.h"
#include "mocks/mock_wallet_ffi_capture.h"
#include <logos_test.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>

#include <nlohmann/json.hpp>

// 64-char hex string = 32 bytes (valid account id).
static const std::string VALID_ID = std::string(64, 'a');
static const std::string VALID_ID_2 = std::string(64, 'b');
// 32-char hex string = 16 bytes (valid amount / solution).
static const std::string VALID_U128 = std::string(32, '1');

// The impl returns serialized JSON strings (Qt-free). Parse them here so tests
// can assert on individual fields.
static nlohmann::json parseObject(const std::string& json) {
    return nlohmann::json::parse(json, nullptr, false);
}

namespace {

    class TemporaryProfileRoot {
    public:
        TemporaryProfileRoot() {
            static std::atomic<uint64_t> sequence{0};
            path = std::filesystem::temp_directory_path() / ("lez-core-tests-" + std::to_string(sequence.fetch_add(1)));
            std::filesystem::remove_all(path);
            std::filesystem::create_directories(path);
        }

        ~TemporaryProfileRoot() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }

        std::filesystem::path defaultPath() const {
            return path / "default";
        }

        void writeCompleteProfile() const {
            std::filesystem::create_directories(defaultPath());
            std::ofstream(defaultPath() / "config.json") << "{}";
            std::ofstream(defaultPath() / "storage.json") << "{}";
        }

        std::filesystem::path path;
    };

    void setProfileContext(LEZCoreModule& module, const TemporaryProfileRoot& root) {
        module._logosCoreSetContext_("/module", "test-instance", root.path.string());
    }

    void assertLifecycleEnvelope(const nlohmann::json& result) {
        LOGOS_ASSERT_TRUE(result.is_object());
        LOGOS_ASSERT_TRUE(result.contains("success"));
        LOGOS_ASSERT_TRUE(result.contains("state"));
        LOGOS_ASSERT_EQ(result["profile"].get<std::string>(), std::string("default"));
        LOGOS_ASSERT_TRUE(result.contains("error_code"));
        LOGOS_ASSERT_TRUE(result.contains("error"));
        LOGOS_ASSERT_FALSE(result.contains("config_path"));
        LOGOS_ASSERT_FALSE(result.contains("storage_path"));
        LOGOS_ASSERT_FALSE(result.contains("statistics_path"));
    }

    void assertGenericEnvelope(const nlohmann::json& result) {
        LOGOS_ASSERT_TRUE(result.is_object());
        LOGOS_ASSERT_TRUE(result.contains("success"));
        LOGOS_ASSERT_TRUE(result.contains("tx_hash"));
        LOGOS_ASSERT_TRUE(result.contains("secrets"));
        LOGOS_ASSERT_TRUE(result["secrets"].is_array());
        LOGOS_ASSERT_TRUE(result.contains("error"));
    }

} // namespace

// ============================================================================
// Plugin metadata
// ============================================================================

LOGOS_TEST(name_and_version) {
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.name(), std::string("lez_core"));
    LOGOS_ASSERT_EQ(module.version(), std::string("0.5.0"));
}

// ============================================================================
// Account management
// ============================================================================

LOGOS_TEST(create_account_public_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const std::string id = module.create_account_public();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_public"));
    // Mock fills the id with 0xAB bytes -> 64 hex chars ("ab" x 32).
    std::string expected;
    for (int i = 0; i < 32; ++i)
        expected += "ab";
    LOGOS_ASSERT_EQ(id, expected);
}

LOGOS_TEST(create_account_public_returns_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_account_public").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.create_account_public().empty());
}

LOGOS_TEST(create_account_private_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const std::string id = module.create_account_private();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_private"));
    std::string expected;
    for (int i = 0; i < 32; ++i)
        expected += "cd";
    LOGOS_ASSERT_EQ(id, expected);
}

LOGOS_TEST(list_accounts_maps_entries) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("list_accounts_count").returns(3);
    LEZCoreModule module;

    const LogosList accounts = module.list_accounts();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_list_accounts"));
    LOGOS_ASSERT_EQ(static_cast<int>(accounts.size()), 3);

    // entry 0 is public, entry 1 is private.
    std::string expectedId0;
    for (int i = 0; i < 32; ++i)
        expectedId0 += "10";
    LOGOS_ASSERT_TRUE(accounts[0]["is_public"].get<bool>());
    LOGOS_ASSERT_EQ(accounts[0]["account_id"].get<std::string>(), expectedId0);
    LOGOS_ASSERT_FALSE(accounts[1]["is_public"].get<bool>());
}

LOGOS_TEST(list_accounts_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_list_accounts").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(static_cast<int>(module.list_accounts().size()), 0);
}

// ============================================================================
// Account queries
// ============================================================================

LOGOS_TEST(get_balance_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.get_balance("not-hex", true).empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_balance"));
}

LOGOS_TEST(get_balance_returns_decimal_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(123456789);
    LEZCoreModule module;

    const std::string balance = module.get_balance(VALID_ID, true);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_balance"));
    LOGOS_ASSERT_EQ(balance, std::string("123456789"));
}

LOGOS_TEST(get_balance_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(0);
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, false), std::string("0"));
}

LOGOS_TEST(get_account_public_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.get_account_public(VALID_ID));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_account_public"));
    // program_owner mocked to 0xAA bytes.
    std::string expectedOwner;
    for (int i = 0; i < 32; ++i)
        expectedOwner += "aa";
    LOGOS_ASSERT_EQ(obj["program_owner"].get<std::string>(), expectedOwner);
}

LOGOS_TEST(get_account_public_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.get_account_public("zz").empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_account_public"));
}

LOGOS_TEST(get_public_account_key_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    std::string expected;
    for (int i = 0; i < 32; ++i)
        expected += "be";
    LOGOS_ASSERT_EQ(module.get_public_account_key(VALID_ID), expected);
}

LOGOS_TEST(get_private_account_keys_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.get_private_account_keys(VALID_ID));
    std::string expected;
    for (int i = 0; i < 32; ++i)
        expected += "ef";
    LOGOS_ASSERT_EQ(obj["nullifier_public_key"].get<std::string>(), expected);
}

// ============================================================================
// Account encoding
// ============================================================================

LOGOS_TEST(account_id_to_base58_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.account_id_to_base58("xyz").empty());
}

LOGOS_TEST(account_id_to_base58_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_to_base58").returns("SomeBase58Value");
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.account_id_to_base58(VALID_ID), std::string("SomeBase58Value"));
}

LOGOS_TEST(account_id_from_base58_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    std::string expected;
    for (int i = 0; i < 32; ++i)
        expected += "5a";
    LOGOS_ASSERT_EQ(module.account_id_from_base58("anything"), expected);
}

LOGOS_TEST(account_id_from_base58_error_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_from_base58").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.account_id_from_base58("anything").empty());
}

// ============================================================================
// Blockchain synchronisation
// ============================================================================

LOGOS_TEST(sync_to_block_forwards_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_sync_to_block").returns(7);
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.sync_to_block(100), static_cast<int64_t>(7));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_sync_to_block"));
}

LOGOS_TEST(get_last_synced_block_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("last_synced_block_value").returns(55);
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), static_cast<int64_t>(55));
}

LOGOS_TEST(get_last_synced_block_error_returns_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_last_synced_block").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), static_cast<int64_t>(0));
}

LOGOS_TEST(get_current_block_height_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("current_block_height_value").returns(999);
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.get_current_block_height(), static_cast<int64_t>(999));
}

// ============================================================================
// Transfers / registration
// ============================================================================

LOGOS_TEST(transfer_public_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_public"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["tx_hash"].get<std::string>(), std::string("0xmocktxhash"));
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(transfer_public_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_public("bad", VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_public"));
}

LOGOS_TEST(transfer_public_invalid_amount_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, "ff"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("amount"));
}

LOGOS_TEST(transfer_public_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_transfer_public").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(transfer_shielded_invalid_keys_json_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    // to_keys_json is not valid JSON object -> parse failure.
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, "not-json", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

// A missing nullifier_public_key must not succeed with a zero key.
LOGOS_TEST(transfer_shielded_missing_nullifier_key_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, "{}", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_misspelled_nullifier_key_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = std::string("{\"nullifierPublicKey\":\"") + std::string(64, 'a') + "\"}";
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_abbreviated_nullifier_key_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = std::string("{\"nullifier_pubkey\":\"") + std::string(64, 'a') + "\"}";
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_nullifier_key_omitted_viewing_key_only_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = std::string("{\"viewing_public_key\":\"") + std::string(64, 'a') + "\"}";
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_nullifier_key_wrong_type_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = "{\"nullifier_public_key\": 12345}";
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

// A non-string viewing_public_key must be rejected, not treated as absent.
LOGOS_TEST(transfer_shielded_viewing_key_wrong_type_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson =
        std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') + "\",\"viewing_public_key\": 12345}";
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson =
        std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') + std::string("\"}");
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

// to_keys_json carrying an explicit "identifier" must be forwarded to the FFI call as-is.
LOGOS_TEST(transfer_shielded_with_identifier_forwards_it_unchanged) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string identifierHex(32, '7'); // 16 bytes of 0x77
    const std::string keysJson = std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') +
                                 "\",\"identifier\":\"" + identifierHex + "\"}";

    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());

    uint8_t expected[16];
    memset(expected, 0x77, sizeof(expected));
    LOGOS_ASSERT(memcmp(MockWalletFfiCapture::lastTransferShieldedIdentifier, expected, sizeof(expected)) == 0);
}

// to_keys_json never carries an identifier in practice -> a random, non-zero one must be
// generated each call (regression guard against reintroducing the old hardcoded-zero identifier).
LOGOS_TEST(transfer_shielded_without_identifier_uses_random_nonzero_identifier) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') + "\"}";

    module.transfer_shielded(VALID_ID, keysJson, VALID_U128);
    uint8_t first[16];
    memcpy(first, MockWalletFfiCapture::lastTransferShieldedIdentifier, sizeof(first));

    module.transfer_shielded(VALID_ID, keysJson, VALID_U128);
    const uint8_t* second = MockWalletFfiCapture::lastTransferShieldedIdentifier;

    uint8_t zero[16] = {0};
    LOGOS_ASSERT_FALSE(memcmp(first, zero, sizeof(first)) == 0);
    LOGOS_ASSERT_FALSE(memcmp(first, second, sizeof(first)) == 0);
}

// transfer_private shares the same parser, so it must reject a missing key too.
LOGOS_TEST(transfer_private_missing_nullifier_key_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.transfer_private(VALID_ID, "{}", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_private"));
}

// transfer_private mirrors transfer_shielded's identifier handling exactly (see above).
LOGOS_TEST(transfer_private_with_identifier_forwards_it_unchanged) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string identifierHex(32, '7'); // 16 bytes of 0x77
    const std::string keysJson = std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') +
                                 "\",\"identifier\":\"" + identifierHex + "\"}";

    const nlohmann::json obj = parseObject(module.transfer_private(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());

    uint8_t expected[16];
    memset(expected, 0x77, sizeof(expected));
    LOGOS_ASSERT(memcmp(MockWalletFfiCapture::lastTransferPrivateIdentifier, expected, sizeof(expected)) == 0);
}

LOGOS_TEST(transfer_private_without_identifier_uses_random_nonzero_identifier) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string keysJson = std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') + "\"}";

    module.transfer_private(VALID_ID, keysJson, VALID_U128);
    uint8_t first[16];
    memcpy(first, MockWalletFfiCapture::lastTransferPrivateIdentifier, sizeof(first));

    module.transfer_private(VALID_ID, keysJson, VALID_U128);
    const uint8_t* second = MockWalletFfiCapture::lastTransferPrivateIdentifier;

    uint8_t zero[16] = {0};
    LOGOS_ASSERT_FALSE(memcmp(first, zero, sizeof(first)) == 0);
    LOGOS_ASSERT_FALSE(memcmp(first, second, sizeof(first)) == 0);
}

LOGOS_TEST(register_public_account_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.register_public_account("bad"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_register_public_account"));
}

LOGOS_TEST(register_private_account_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.register_private_account(VALID_ID));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_register_private_account"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

// ============================================================================
// Bridge (L1 Bedrock <-> L2)
// ============================================================================

LOGOS_TEST(bridge_withdraw_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.bridge_withdraw(VALID_ID, VALID_ID_2, 100));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_bridge_withdraw"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["tx_hash"].get<std::string>(), std::string("0xmocktxhash"));
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(bridge_withdraw_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.bridge_withdraw("bad", VALID_ID_2, 100));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_bridge_withdraw"));
}

LOGOS_TEST(bridge_withdraw_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_bridge_withdraw").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.bridge_withdraw(VALID_ID, VALID_ID_2, 100));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

// ============================================================================
// Vault claiming
// ============================================================================

LOGOS_TEST(get_vault_balance_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.get_vault_balance("not-hex").empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_vault_balance"));
}

LOGOS_TEST(get_vault_balance_returns_decimal_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_vault_balance_value").returns(42);
    LEZCoreModule module;

    const std::string balance = module.get_vault_balance(VALID_ID);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_vault_balance"));
    LOGOS_ASSERT_EQ(balance, std::string("42"));
}

LOGOS_TEST(get_vault_balance_ffi_error_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_vault_balance").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.get_vault_balance(VALID_ID).empty());
}

LOGOS_TEST(vault_claim_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim(VALID_ID, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_vault_claim"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["tx_hash"].get<std::string>(), std::string("0xmocktxhash"));
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(vault_claim_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim("bad", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_vault_claim"));
}

LOGOS_TEST(vault_claim_invalid_amount_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim(VALID_ID, "ff"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("amount"));
}

LOGOS_TEST(vault_claim_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_vault_claim").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim(VALID_ID, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(vault_claim_private_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim_private(VALID_ID, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_vault_claim_private"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

LOGOS_TEST(vault_claim_private_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim_private("bad", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_vault_claim_private"));
}

LOGOS_TEST(vault_claim_private_invalid_amount_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim_private(VALID_ID, "ff"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("amount"));
}

LOGOS_TEST(vault_claim_private_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_vault_claim_private").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.vault_claim_private(VALID_ID, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

// ============================================================================
// Pinata claiming
// ============================================================================

LOGOS_TEST(claim_pinata_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata("bad", VALID_ID_2, VALID_U128).empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_invalid_solution_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata(VALID_ID, VALID_ID_2, "ab").empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.claim_pinata(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

LOGOS_TEST(claim_pinata_already_initialized_invalid_siblings_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    // siblings json is not an array -> parse failure.
    const std::string result =
        module.claim_pinata_private_owned_already_initialized(VALID_ID, VALID_ID_2, VALID_U128, 0, "not-an-array");
    LOGOS_ASSERT_TRUE(result.empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
}

LOGOS_TEST(claim_pinata_already_initialized_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const std::string siblings =
        std::string("[\"") + std::string(64, 'a') + std::string("\",\"") + std::string(64, 'b') + std::string("\"]");
    const nlohmann::json obj = parseObject(
        module.claim_pinata_private_owned_already_initialized(VALID_ID, VALID_ID_2, VALID_U128, 1, siblings)
    );
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

// ============================================================================
// Generic public transactions
// ============================================================================

LOGOS_TEST(generic_public_rejects_empty_accounts_before_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({}, {}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_resolve_public_account"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_send_generic_public_transaction"));
}

LOGOS_TEST(generic_public_rejects_mismatched_signing_vector_before_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("equal lengths"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_resolve_public_account"));
}

LOGOS_TEST(generic_public_rejects_empty_instruction_before_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {true}, {}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("instruction"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_resolve_public_account"));
}

LOGOS_TEST(generic_public_rejects_malformed_program_before_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {true}, {1}, "bad"));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_resolve_public_account"));
}

LOGOS_TEST(generic_public_rejects_malformed_account_before_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const nlohmann::json obj =
        parseObject(module.send_generic_public_transaction({VALID_ID, "bad"}, {true, false}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_resolve_public_account"));
}

LOGOS_TEST(generic_public_ffi_error_uses_consistent_envelope) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    t.mockCFunction("wallet_ffi_send_generic_public_transaction").returns(static_cast<int>(INTERNAL_ERROR));
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {true}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_TRUE(obj["tx_hash"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(generic_public_requires_nonempty_transaction_hash) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    t.mockCFunction("transaction_tx_hash_empty").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {true}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_TRUE(obj["tx_hash"].get<std::string>().empty());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("empty transaction hash"));
}

LOGOS_TEST(generic_public_success_returns_hash_and_empty_secrets) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    const nlohmann::json obj = parseObject(module.send_generic_public_transaction({VALID_ID}, {true}, {1}, VALID_ID));
    assertGenericEnvelope(obj);
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["tx_hash"].get<std::string>().empty());
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
}

// ============================================================================
// Wallet lifecycle
// ============================================================================

LOGOS_TEST(wallet_status_without_host_context_is_typed_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LEZCoreModule module;

    const nlohmann::json obj = parseObject(module.wallet_status());
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["state"].get<std::string>(), std::string("error"));
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("context_unavailable"));
}

LOGOS_TEST(wallet_status_reports_absent_default_profile_as_closed) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.wallet_status());
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["state"].get<std::string>(), std::string("closed"));
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
}

LOGOS_TEST(wallet_status_reports_partial_default_profile_as_error) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    std::filesystem::create_directories(root.defaultPath());
    std::ofstream(root.defaultPath() / "config.json") << "{}";
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.wallet_status());
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("profile_incomplete"));
}

LOGOS_TEST(create_default_uses_host_owned_canonical_paths_and_saves) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.create_default("password"));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["state"].get<std::string>(), std::string("open"));
    LOGOS_ASSERT_EQ(obj["mnemonic"].get<std::string>(), std::string("word word"));
    LOGOS_ASSERT_EQ(MockWalletFfiCapture::lastCreateConfigPath, (root.defaultPath() / "config.json").string());
    LOGOS_ASSERT_EQ(MockWalletFfiCapture::lastCreateStoragePath, (root.defaultPath() / "storage.json").string());
    LOGOS_ASSERT_EQ(MockWalletFfiCapture::lastCreateStatisticsPath, (root.defaultPath() / "statistics.json").string());
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_save"));
    LOGOS_ASSERT_TRUE(obj.dump().find(root.path.string()) == std::string::npos);
    const std::filesystem::perms profilePermissions = std::filesystem::status(root.defaultPath()).permissions();
    LOGOS_ASSERT_TRUE((profilePermissions & std::filesystem::perms::owner_all) == std::filesystem::perms::owner_all);
    LOGOS_ASSERT_TRUE((profilePermissions & std::filesystem::perms::group_all) == std::filesystem::perms::none);
    LOGOS_ASSERT_TRUE((profilePermissions & std::filesystem::perms::others_all) == std::filesystem::perms::none);
}

LOGOS_TEST(create_default_rejects_empty_password_before_filesystem_or_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.create_default(""));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("invalid_password"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
}

LOGOS_TEST(create_default_rejects_existing_profile_without_calling_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    root.writeCompleteProfile();
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.create_default("password"));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("profile_exists"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
}

LOGOS_TEST(open_default_is_idempotent_for_same_profile) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    TemporaryProfileRoot root;
    root.writeCompleteProfile();
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json first = parseObject(module.open_default());
    const nlohmann::json second = parseObject(module.open_default());
    LOGOS_ASSERT_TRUE(first["success"].get<bool>());
    LOGOS_ASSERT_TRUE(second["success"].get<bool>());
    LOGOS_ASSERT_EQ(LogosCMockStore::instance().callCount("wallet_ffi_open"), 1);
    LOGOS_ASSERT_EQ(MockWalletFfiCapture::lastOpenConfigPath, (root.defaultPath() / "config.json").string());
}

LOGOS_TEST(open_default_rejects_absent_profile_without_calling_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.open_default());
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("profile_not_found"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_open"));

    const nlohmann::json status = parseObject(module.wallet_status());
    LOGOS_ASSERT_TRUE(status["success"].get<bool>());
    LOGOS_ASSERT_EQ(status["state"].get<std::string>(), std::string("closed"));
}

LOGOS_TEST(default_lifecycle_refuses_to_replace_external_open_handle) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);
    LOGOS_ASSERT_EQ(
        module.open("/external/config", "/external/storage", "/external/stats"), static_cast<int64_t>(SUCCESS)
    );

    const nlohmann::json openResult = parseObject(module.open_default());
    const nlohmann::json createResult = parseObject(module.create_default("password"));
    LOGOS_ASSERT_FALSE(openResult["success"].get<bool>());
    LOGOS_ASSERT_FALSE(createResult["success"].get<bool>());
    LOGOS_ASSERT_EQ(openResult["error_code"].get<std::string>(), std::string("wallet_already_open"));
    LOGOS_ASSERT_EQ(LogosCMockStore::instance().callCount("wallet_ffi_open"), 1);
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
}

LOGOS_TEST(restore_default_saves_and_never_returns_mnemonic) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.restore_default("existing recovery words", "password", 4));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj.contains("mnemonic"));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_restore_data"));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_save"));
}

LOGOS_TEST(restore_default_rejects_invalid_inputs_before_filesystem_or_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json missingMnemonic = parseObject(module.restore_default("", "password", 4));
    const nlohmann::json missingPassword = parseObject(module.restore_default("recovery words", "", 4));
    LOGOS_ASSERT_EQ(missingMnemonic["error_code"].get<std::string>(), std::string("invalid_mnemonic"));
    LOGOS_ASSERT_EQ(missingPassword["error_code"].get<std::string>(), std::string("invalid_password"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_restore_data"));
}

LOGOS_TEST(restore_default_rejects_excessive_depth_before_filesystem_or_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.restore_default("recovery words", "password", 11));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("invalid_depth"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_restore_data"));
}

LOGOS_TEST(restore_default_rejects_existing_profile_without_calling_ffi) {
    auto t = LogosTestContext("logos_execution_zone");
    TemporaryProfileRoot root;
    root.writeCompleteProfile();
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.restore_default("recovery words", "password", 4));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("profile_exists"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_create_new"));
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_restore_data"));
}

LOGOS_TEST(restore_default_rolls_back_incomplete_profile_on_restore_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    t.mockCFunction("wallet_ffi_restore_data").returns(static_cast<int>(INTERNAL_ERROR));
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.restore_default("existing recovery words", "password", 4));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("restore_failed"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_destroy"));
}

LOGOS_TEST(create_default_rolls_back_on_save_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    t.mockCFunction("wallet_ffi_save").returns(static_cast<int>(INTERNAL_ERROR));
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.create_default("password"));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("save_failed"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
}

LOGOS_TEST(restore_default_rolls_back_on_save_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    t.mockCFunction("wallet_ffi_save").returns(static_cast<int>(INTERNAL_ERROR));
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    const nlohmann::json obj = parseObject(module.restore_default("recovery words", "password", 4));
    assertLifecycleEnvelope(obj);
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["error_code"].get<std::string>(), std::string("save_failed"));
    LOGOS_ASSERT_FALSE(std::filesystem::exists(root.defaultPath()));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_destroy"));
}

LOGOS_TEST(concurrent_create_default_calls_are_serialized) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1);
    TemporaryProfileRoot root;
    LEZCoreModule module;
    setProfileContext(module, root);

    auto first =
        std::async(std::launch::async, [&module]() { return parseObject(module.create_default("password-one")); });
    auto second =
        std::async(std::launch::async, [&module]() { return parseObject(module.create_default("password-two")); });
    const nlohmann::json firstResult = first.get();
    const nlohmann::json secondResult = second.get();

    const int successes =
        static_cast<int>(firstResult["success"].get<bool>()) + static_cast<int>(secondResult["success"].get<bool>());
    LOGOS_ASSERT_EQ(successes, 1);
    LOGOS_ASSERT_EQ(LogosCMockStore::instance().callCount("wallet_ffi_create_new"), 1);
}

LOGOS_TEST(create_new_success_then_double_open_fails) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1); // non-null handle
    LEZCoreModule module;

    LOGOS_ASSERT_TRUE(!module.create_new("/cfg", "/store", "/stats", "pw").empty());
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_new"));
    // Second attempt: already open.
    LOGOS_ASSERT_EQ(module.create_new("/cfg", "/store", "/stats", "pw"), "");
}

LOGOS_TEST(create_new_null_handle_returns_internal_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(0); // null handle
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.create_new("/cfg", "/store", "/stats", "pw"), "");
}

LOGOS_TEST(open_success) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_open"));
}

LOGOS_TEST(save_forwards_return_code) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    t.mockCFunction("wallet_ffi_save").returns(static_cast<int>(SUCCESS));
    LEZCoreModule module;
    LOGOS_ASSERT_EQ(module.open("/cfg", "/store", "/stats"), static_cast<int64_t>(SUCCESS));

    LOGOS_ASSERT_EQ(module.save(), static_cast<int64_t>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_save"));
}

// ============================================================================
// Configuration
// ============================================================================

LOGOS_TEST(get_sequencer_addr_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_sequencer_addr").returns("10.0.0.1:9000");
    LEZCoreModule module;

    LOGOS_ASSERT_EQ(module.get_sequencer_addr(), std::string("10.0.0.1:9000"));
}
