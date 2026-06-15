// Unit tests for LogosExecutionZoneWalletModule.
// All wallet_ffi C functions are mocked at link time via mock_wallet_ffi.cpp.

#include <logos_test.h>
#include "logos_execution_zone_wallet_module.h"

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

// ============================================================================
// Plugin metadata
// ============================================================================

LOGOS_TEST(name_and_version) {
    LogosExecutionZoneWalletModule module;
    LOGOS_ASSERT_EQ(module.name(), std::string("logos_execution_zone"));
    LOGOS_ASSERT_EQ(module.version(), std::string("1.0.0"));
}

// ============================================================================
// Account management
// ============================================================================

LOGOS_TEST(create_account_public_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const std::string id = module.create_account_public();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_public"));
    // Mock fills the id with 0xAB bytes -> 64 hex chars ("ab" x 32).
    std::string expected;
    for (int i = 0; i < 32; ++i) expected += "ab";
    LOGOS_ASSERT_EQ(id, expected);
}

LOGOS_TEST(create_account_public_returns_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_account_public").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.create_account_public().empty());
}

LOGOS_TEST(create_account_private_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const std::string id = module.create_account_private();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_private"));
    std::string expected;
    for (int i = 0; i < 32; ++i) expected += "cd";
    LOGOS_ASSERT_EQ(id, expected);
}

LOGOS_TEST(list_accounts_maps_entries) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("list_accounts_count").returns(3);
    LogosExecutionZoneWalletModule module;

    const LogosList accounts = module.list_accounts();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_list_accounts"));
    LOGOS_ASSERT_EQ(static_cast<int>(accounts.size()), 3);

    // entry 0 is public, entry 1 is private.
    std::string expectedId0;
    for (int i = 0; i < 32; ++i) expectedId0 += "10";
    LOGOS_ASSERT_TRUE(accounts[0]["is_public"].get<bool>());
    LOGOS_ASSERT_EQ(accounts[0]["account_id"].get<std::string>(), expectedId0);
    LOGOS_ASSERT_FALSE(accounts[1]["is_public"].get<bool>());
}

LOGOS_TEST(list_accounts_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_list_accounts").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(static_cast<int>(module.list_accounts().size()), 0);
}

// ============================================================================
// Account queries
// ============================================================================

LOGOS_TEST(get_balance_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.get_balance("not-hex", true).empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_balance"));
}

LOGOS_TEST(get_balance_returns_decimal_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(123456789);
    LogosExecutionZoneWalletModule module;

    const std::string balance = module.get_balance(VALID_ID, true);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_balance"));
    LOGOS_ASSERT_EQ(balance, std::string("123456789"));
}

LOGOS_TEST(get_balance_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(0);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, false), std::string("0"));
}

LOGOS_TEST(get_account_public_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.get_account_public(VALID_ID));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_account_public"));
    // program_owner mocked to 0xAA bytes.
    std::string expectedOwner;
    for (int i = 0; i < 32; ++i) expectedOwner += "aa";
    LOGOS_ASSERT_EQ(obj["program_owner"].get<std::string>(), expectedOwner);
}

LOGOS_TEST(get_account_public_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.get_account_public("zz").empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_account_public"));
}

LOGOS_TEST(get_public_account_key_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    std::string expected;
    for (int i = 0; i < 32; ++i) expected += "be";
    LOGOS_ASSERT_EQ(module.get_public_account_key(VALID_ID), expected);
}

LOGOS_TEST(get_private_account_keys_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.get_private_account_keys(VALID_ID));
    std::string expected;
    for (int i = 0; i < 32; ++i) expected += "ef";
    LOGOS_ASSERT_EQ(obj["nullifier_public_key"].get<std::string>(), expected);
}

// ============================================================================
// Account encoding
// ============================================================================

LOGOS_TEST(account_id_to_base58_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.account_id_to_base58("xyz").empty());
}

LOGOS_TEST(account_id_to_base58_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_to_base58").returns("SomeBase58Value");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.account_id_to_base58(VALID_ID), std::string("SomeBase58Value"));
}

LOGOS_TEST(account_id_from_base58_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    std::string expected;
    for (int i = 0; i < 32; ++i) expected += "5a";
    LOGOS_ASSERT_EQ(module.account_id_from_base58("anything"), expected);
}

LOGOS_TEST(account_id_from_base58_error_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_from_base58").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.account_id_from_base58("anything").empty());
}

// ============================================================================
// Blockchain synchronisation
// ============================================================================

LOGOS_TEST(sync_to_block_forwards_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_sync_to_block").returns(7);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.sync_to_block(100), static_cast<int64_t>(7));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_sync_to_block"));
}

LOGOS_TEST(get_last_synced_block_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("last_synced_block_value").returns(55);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), static_cast<int64_t>(55));
}

LOGOS_TEST(get_last_synced_block_error_returns_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_last_synced_block").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), static_cast<int64_t>(0));
}

LOGOS_TEST(get_current_block_height_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("current_block_height_value").returns(999);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_current_block_height(), static_cast<int64_t>(999));
}

// ============================================================================
// Transfers / registration
// ============================================================================

LOGOS_TEST(transfer_public_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_public"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
    LOGOS_ASSERT_EQ(obj["tx_hash"].get<std::string>(), std::string("0xmocktxhash"));
    LOGOS_ASSERT_TRUE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(transfer_public_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.transfer_public("bad", VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_public"));
}

LOGOS_TEST(transfer_public_invalid_amount_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, "ff"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_CONTAINS(obj["error"].get<std::string>(), std::string("amount"));
}

LOGOS_TEST(transfer_public_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_transfer_public").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(obj["error"].get<std::string>().empty());
}

LOGOS_TEST(transfer_shielded_invalid_keys_json_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    // to_keys_json is not valid JSON object -> parse failure.
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, "not-json", VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const std::string keysJson = std::string("{\"nullifier_public_key\":\"") + std::string(64, 'a') + std::string("\"}");
    const nlohmann::json obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

LOGOS_TEST(register_public_account_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.register_public_account("bad"));
    LOGOS_ASSERT_FALSE(obj["success"].get<bool>());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_register_public_account"));
}

LOGOS_TEST(register_private_account_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.register_private_account(VALID_ID));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_register_private_account"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

// ============================================================================
// Pinata claiming
// ============================================================================

LOGOS_TEST(claim_pinata_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata("bad", VALID_ID_2, VALID_U128).empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_invalid_solution_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata(VALID_ID, VALID_ID_2, "ab").empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const nlohmann::json obj = parseObject(module.claim_pinata(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

LOGOS_TEST(claim_pinata_already_initialized_invalid_siblings_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    // siblings json is not an array -> parse failure.
    const std::string result = module.claim_pinata_private_owned_already_initialized(
        VALID_ID, VALID_ID_2, VALID_U128, 0, "not-an-array");
    LOGOS_ASSERT_TRUE(result.empty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
}

LOGOS_TEST(claim_pinata_already_initialized_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const std::string siblings = std::string("[\"") + std::string(64, 'a') + std::string("\",\"") + std::string(64, 'b') + std::string("\"]");
    const nlohmann::json obj = parseObject(module.claim_pinata_private_owned_already_initialized(
        VALID_ID, VALID_ID_2, VALID_U128, 1, siblings));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
    LOGOS_ASSERT_TRUE(obj["success"].get<bool>());
}

// ============================================================================
// Wallet lifecycle
// ============================================================================

LOGOS_TEST(create_new_success_then_double_open_fails) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1); // non-null handle
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.create_new("/cfg", "/store", "pw"), static_cast<int64_t>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_new"));
    // Second attempt: already open.
    LOGOS_ASSERT_EQ(module.create_new("/cfg", "/store", "pw"), static_cast<int64_t>(INTERNAL_ERROR));
}

LOGOS_TEST(create_new_null_handle_returns_internal_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(0); // null handle
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.create_new("/cfg", "/store", "pw"), static_cast<int64_t>(INTERNAL_ERROR));
}

LOGOS_TEST(open_success) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.open("/cfg", "/store"), static_cast<int64_t>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_open"));
}

LOGOS_TEST(save_forwards_return_code) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_save").returns(static_cast<int>(SUCCESS));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.save(), static_cast<int64_t>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_save"));
}

// ============================================================================
// Configuration
// ============================================================================

LOGOS_TEST(get_sequencer_addr_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_sequencer_addr").returns("10.0.0.1:9000");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_sequencer_addr(), std::string("10.0.0.1:9000"));
}
