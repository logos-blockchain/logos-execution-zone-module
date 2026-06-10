// Unit tests for LogosExecutionZoneWalletModule.
// All wallet_ffi C functions are mocked at link time via mock_wallet_ffi.cpp.

#include <logos_test.h>
#include "logos_execution_zone_wallet_module.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

// 64-char hex string = 32 bytes (valid account id).
static const QString VALID_ID = QString(64, 'a');
static const QString VALID_ID_2 = QString(64, 'b');
// 32-char hex string = 16 bytes (valid amount / solution).
static const QString VALID_U128 = QString(32, '1');

static QJsonObject parseObject(const QString& json) {
    return QJsonDocument::fromJson(json.toUtf8()).object();
}

// ============================================================================
// Plugin metadata
// ============================================================================

LOGOS_TEST(name_and_version) {
    LogosExecutionZoneWalletModule module;
    LOGOS_ASSERT_EQ(module.name(), QStringLiteral("logos_execution_zone"));
    LOGOS_ASSERT_EQ(module.version(), QStringLiteral("1.0.0"));
}

// ============================================================================
// Account management
// ============================================================================

LOGOS_TEST(create_account_public_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QString id = module.create_account_public();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_public"));
    // Mock fills the id with 0xAB bytes -> 64 hex chars ("ab" x 32).
    LOGOS_ASSERT_EQ(id, QString("ab").repeated(32));
}

LOGOS_TEST(create_account_public_returns_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_account_public").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.create_account_public().isEmpty());
}

LOGOS_TEST(create_account_private_returns_hex_on_success) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QString id = module.create_account_private();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_account_private"));
    LOGOS_ASSERT_EQ(id, QString("cd").repeated(32));
}

LOGOS_TEST(list_accounts_maps_entries) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("list_accounts_count").returns(3);
    LogosExecutionZoneWalletModule module;

    const QJsonArray accounts = module.list_accounts();
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_list_accounts"));
    LOGOS_ASSERT_EQ(accounts.size(), 3);

    // list_accounts appends JSON objects (ffiAccountListEntryToJson returns a
    // QJsonObject); entry 0 is public, entry 1 is private.
    const QJsonObject e0 = accounts[0].toObject();
    LOGOS_ASSERT_TRUE(e0["is_public"].toBool());
    LOGOS_ASSERT_EQ(e0["account_id"].toString(), QString("10").repeated(32));
    const QJsonObject e1 = accounts[1].toObject();
    LOGOS_ASSERT_FALSE(e1["is_public"].toBool());
}

LOGOS_TEST(list_accounts_empty_on_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_list_accounts").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.list_accounts().size(), 0);
}

// ============================================================================
// Account queries
// ============================================================================

LOGOS_TEST(get_balance_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.get_balance(QStringLiteral("not-hex"), true).isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_balance"));
}

LOGOS_TEST(get_balance_returns_decimal_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(123456789);
    LogosExecutionZoneWalletModule module;

    const QString balance = module.get_balance(VALID_ID, true);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_balance"));
    LOGOS_ASSERT_EQ(balance, QStringLiteral("123456789"));
}

LOGOS_TEST(get_balance_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(0);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, false), QStringLiteral("0"));
}

LOGOS_TEST(get_balance_string_overload_parses_bool) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("get_balance_value").returns(42);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, QStringLiteral("true")), QStringLiteral("42"));
    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, QStringLiteral("1")), QStringLiteral("42"));
    LOGOS_ASSERT_EQ(module.get_balance(VALID_ID, QStringLiteral("yes")), QStringLiteral("42"));
}

LOGOS_TEST(get_account_public_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QString json = module.get_account_public(VALID_ID);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_get_account_public"));
    const QJsonObject obj = parseObject(json);
    // program_owner mocked to 0xAA bytes.
    LOGOS_ASSERT_EQ(obj["program_owner"].toString(), QString("aa").repeated(32));
}

LOGOS_TEST(get_account_public_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.get_account_public(QStringLiteral("zz")).isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_get_account_public"));
}

LOGOS_TEST(get_public_account_key_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_public_account_key(VALID_ID), QString("be").repeated(32));
}

LOGOS_TEST(get_private_account_keys_returns_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.get_private_account_keys(VALID_ID));
    LOGOS_ASSERT_EQ(obj["nullifier_public_key"].toString(), QString("ef").repeated(32));
}

// ============================================================================
// Account encoding
// ============================================================================

LOGOS_TEST(account_id_to_base58_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.account_id_to_base58(QStringLiteral("xyz")).isEmpty());
}

LOGOS_TEST(account_id_to_base58_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_to_base58").returns("SomeBase58Value");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.account_id_to_base58(VALID_ID), QStringLiteral("SomeBase58Value"));
}

LOGOS_TEST(account_id_from_base58_returns_hex) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.account_id_from_base58(QStringLiteral("anything")), QString("5a").repeated(32));
}

LOGOS_TEST(account_id_from_base58_error_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_account_id_from_base58").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.account_id_from_base58(QStringLiteral("anything")).isEmpty());
}

// ============================================================================
// Blockchain synchronisation
// ============================================================================

LOGOS_TEST(sync_to_block_string_invalid_returns_negative_one) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.sync_to_block(QStringLiteral("notnum")), -1);
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_sync_to_block"));
}

LOGOS_TEST(sync_to_block_string_valid_forwards) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_sync_to_block").returns(7);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.sync_to_block(QStringLiteral("100")), 7);
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_sync_to_block"));
}

LOGOS_TEST(get_last_synced_block_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("last_synced_block_value").returns(55);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), 55);
}

LOGOS_TEST(get_last_synced_block_error_returns_zero) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_last_synced_block").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_last_synced_block(), 0);
}

LOGOS_TEST(get_current_block_height_returns_value) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("current_block_height_value").returns(999);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_current_block_height(), 999);
}

// ============================================================================
// Transfers / registration
// ============================================================================

LOGOS_TEST(transfer_public_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_public"));
    LOGOS_ASSERT_TRUE(obj["success"].toBool());
    LOGOS_ASSERT_EQ(obj["tx_hash"].toString(), QStringLiteral("0xmocktxhash"));
    LOGOS_ASSERT_TRUE(obj["error"].toString().isEmpty());
}

LOGOS_TEST(transfer_public_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.transfer_public(QStringLiteral("bad"), VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].toBool());
    LOGOS_ASSERT_FALSE(obj["error"].toString().isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_public"));
}

LOGOS_TEST(transfer_public_invalid_amount_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, QStringLiteral("ff")));
    LOGOS_ASSERT_FALSE(obj["success"].toBool());
    LOGOS_ASSERT_CONTAINS(obj["error"].toString().toStdString(), std::string("amount"));
}

LOGOS_TEST(transfer_public_ffi_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_transfer_public").returns(static_cast<int>(INTERNAL_ERROR));
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.transfer_public(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].toBool());
    LOGOS_ASSERT_FALSE(obj["error"].toString().isEmpty());
}

LOGOS_TEST(transfer_shielded_invalid_keys_json_error) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    // to_keys_json is not valid JSON object -> parse failure.
    const QJsonObject obj = parseObject(module.transfer_shielded(VALID_ID, QStringLiteral("not-json"), VALID_U128));
    LOGOS_ASSERT_FALSE(obj["success"].toBool());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
}

LOGOS_TEST(transfer_shielded_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QString keysJson = QStringLiteral("{\"nullifier_public_key\":\"") + QString(64, 'a') + QStringLiteral("\"}");
    const QJsonObject obj = parseObject(module.transfer_shielded(VALID_ID, keysJson, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_transfer_shielded"));
    LOGOS_ASSERT_TRUE(obj["success"].toBool());
}

LOGOS_TEST(register_public_account_invalid_hex_error_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.register_public_account(QStringLiteral("bad")));
    LOGOS_ASSERT_FALSE(obj["success"].toBool());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_register_public_account"));
}

LOGOS_TEST(register_private_account_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.register_private_account(VALID_ID));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_register_private_account"));
    LOGOS_ASSERT_TRUE(obj["success"].toBool());
}

// ============================================================================
// Pinata claiming
// ============================================================================

LOGOS_TEST(claim_pinata_invalid_hex_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata(QStringLiteral("bad"), VALID_ID_2, VALID_U128).isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_invalid_solution_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_TRUE(module.claim_pinata(VALID_ID, VALID_ID_2, QStringLiteral("ab")).isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata"));
}

LOGOS_TEST(claim_pinata_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QJsonObject obj = parseObject(module.claim_pinata(VALID_ID, VALID_ID_2, VALID_U128));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata"));
    LOGOS_ASSERT_TRUE(obj["success"].toBool());
}

LOGOS_TEST(claim_pinata_already_initialized_invalid_siblings_returns_empty) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    // siblings json is not an array -> parse failure.
    const QString result = module.claim_pinata_private_owned_already_initialized(
        VALID_ID, VALID_ID_2, VALID_U128, 0, QStringLiteral("not-an-array"));
    LOGOS_ASSERT_TRUE(result.isEmpty());
    LOGOS_ASSERT_FALSE(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
}

LOGOS_TEST(claim_pinata_already_initialized_success_json) {
    auto t = LogosTestContext("logos_execution_zone");
    LogosExecutionZoneWalletModule module;

    const QString siblings = QStringLiteral("[\"") + QString(64, 'a') + QStringLiteral("\",\"") + QString(64, 'b') + QStringLiteral("\"]");
    const QJsonObject obj = parseObject(module.claim_pinata_private_owned_already_initialized(
        VALID_ID, VALID_ID_2, VALID_U128, 1, siblings));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_claim_pinata_private_owned_already_initialized"));
    LOGOS_ASSERT_TRUE(obj["success"].toBool());
}

// ============================================================================
// Wallet lifecycle
// ============================================================================

LOGOS_TEST(create_new_success_then_double_open_fails) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(1); // non-null handle
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.create_new(QStringLiteral("/cfg"), QStringLiteral("/store"), QStringLiteral("pw")),
                    static_cast<int>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_create_new"));
    // Second attempt: already open.
    LOGOS_ASSERT_EQ(module.create_new(QStringLiteral("/cfg"), QStringLiteral("/store"), QStringLiteral("pw")),
                    static_cast<int>(INTERNAL_ERROR));
}

LOGOS_TEST(create_new_null_handle_returns_internal_error) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_create_new").returns(0); // null handle
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.create_new(QStringLiteral("/cfg"), QStringLiteral("/store"), QStringLiteral("pw")),
                    static_cast<int>(INTERNAL_ERROR));
}

LOGOS_TEST(open_success) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_open").returns(1);
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.open(QStringLiteral("/cfg"), QStringLiteral("/store")), static_cast<int>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_open"));
}

LOGOS_TEST(save_forwards_return_code) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_save").returns(static_cast<int>(SUCCESS));
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.save(), static_cast<int>(SUCCESS));
    LOGOS_ASSERT(t.cFunctionCalled("wallet_ffi_save"));
}

// ============================================================================
// Configuration
// ============================================================================

LOGOS_TEST(get_sequencer_addr_returns_string) {
    auto t = LogosTestContext("logos_execution_zone");
    t.mockCFunction("wallet_ffi_get_sequencer_addr").returns("10.0.0.1:9000");
    LogosExecutionZoneWalletModule module;

    LOGOS_ASSERT_EQ(module.get_sequencer_addr(), QStringLiteral("10.0.0.1:9000"));
}
