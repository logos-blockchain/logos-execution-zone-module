#include "logos_execution_zone_wallet_module.h"

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QVariantMap>

static QString bytesToHex(const uint8_t* data, const size_t length) {
    const QByteArray bytearray(reinterpret_cast<const char*>(data), static_cast<int>(length));
    return QString::fromLatin1(bytearray.toHex());
}

namespace JsonKeys {
static constexpr auto TxHash = "tx_hash";
static constexpr auto Success = "success";
static constexpr auto ProgramOwner = "program_owner";
static constexpr auto Balance = "balance";
static constexpr auto Nonce = "nonce";
static constexpr auto Data = "data";
static constexpr auto NullifierPublicKey = "nullifier_public_key";
static constexpr auto ViewingPublicKey = "viewing_public_key";
static constexpr auto AccountId = "account_id";
static constexpr auto IsPublic = "is_public";
} // namespace JsonKeys

static bool hexToBytes(const QString& hex, QByteArray& output_bytes, int expectedLength = -1) {
    QString trimmed_hex = hex.trimmed();
    if (trimmed_hex.startsWith("0x", Qt::CaseInsensitive))
        trimmed_hex = trimmed_hex.mid(2);
    if (trimmed_hex.size() % 2 != 0)
        return false;
    const QByteArray decoded = QByteArray::fromHex(trimmed_hex.toLatin1());
    if (expectedLength != -1 && decoded.size() != expectedLength)
        return false;
    output_bytes = decoded;
    return true;
}

static bool hexToU128(const QString& hex, uint8_t (*output)[16]) {
    QByteArray buffer;
    if (!hexToBytes(hex, buffer, 16))
        return false;
    memcpy(output, buffer.constData(), 16);
    return true;
}

static QString bytes32ToHex(const FfiBytes32& bytes) {
    return bytesToHex(bytes.data, 32);
}

static bool hexToBytes32(const QString& hex, FfiBytes32* output_bytes) {
    if (output_bytes == nullptr)
        return false;
    QByteArray buffer;
    if (!hexToBytes(hex, buffer, 32))
        return false;
    memcpy(output_bytes->data, buffer.constData(), 32);
    return true;
}

static QString ffiTransferResultToJson(const FfiTransferResult& result) {
    QVariantMap map;
    map[JsonKeys::TxHash] = result.tx_hash ? QString::fromUtf8(result.tx_hash) : QString();
    map[JsonKeys::Success] = result.success;
    return QJsonDocument(QJsonObject::fromVariantMap(map)).toJson(QJsonDocument::Compact);
}

static QString ffiAccountToJson(const FfiAccount& account) {
    QVariantMap map;
    map[JsonKeys::ProgramOwner] = bytesToHex(reinterpret_cast<const uint8_t*>(account.program_owner.data), 32);
    map[JsonKeys::Balance] = bytesToHex(account.balance.data, 16);
    map[JsonKeys::Nonce] = bytesToHex(account.nonce.data, 16);
    if (account.data && account.data_len > 0) {
        map[JsonKeys::Data] = bytesToHex(account.data, account.data_len);
    } else {
        map[JsonKeys::Data] = QString();
    }
    return QJsonDocument(QJsonObject::fromVariantMap(map)).toJson(QJsonDocument::Compact);
}

static QJsonObject ffiAccountListEntryToJson(const FfiAccountListEntry& entry) {
    QVariantMap map;
    map[JsonKeys::AccountId] = bytes32ToHex(entry.account_id);
    map[JsonKeys::IsPublic] = entry.is_public;
    return QJsonObject::fromVariantMap(map);
}

static QString ffiPrivateAccountKeysToJson(const FfiPrivateAccountKeys& keys) {
    QVariantMap map;
    map[JsonKeys::NullifierPublicKey] = bytes32ToHex(keys.nullifier_public_key);
    if (keys.viewing_public_key && keys.viewing_public_key_len > 0) {
        map[JsonKeys::ViewingPublicKey] = bytesToHex(keys.viewing_public_key, keys.viewing_public_key_len);
    } else {
        map[JsonKeys::ViewingPublicKey] = QString();
    }
    return QJsonDocument(QJsonObject::fromVariantMap(map)).toJson(QJsonDocument::Compact);
}

static bool jsonToFfiPrivateAccountKeys(const QString& json, FfiPrivateAccountKeys* output_keys) {
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject())
        return false;
    const QVariantMap map = doc.object().toVariantMap();

    if (map.contains(JsonKeys::NullifierPublicKey)) {
        if (!hexToBytes32(map[JsonKeys::NullifierPublicKey].toString(), &output_keys->nullifier_public_key))
            return false;
    }

    if (map.contains(JsonKeys::ViewingPublicKey)) {
        QByteArray buffer;
        if (!hexToBytes(map[JsonKeys::ViewingPublicKey].toString(), buffer))
            return false;

        uint8_t* data = static_cast<uint8_t*>(malloc(buffer.size()));
        memcpy(data, buffer.constData(), buffer.size());
        output_keys->viewing_public_key = data;
        output_keys->viewing_public_key_len = buffer.size();
    } else {
        output_keys->viewing_public_key = nullptr;
        output_keys->viewing_public_key_len = 0;
    }

    return true;
}

// Parses a JSON array of 32-byte hex strings into a contiguous byte buffer of siblings.
// Returns true on success, with out_len set to the number of siblings and out_bytes sized to out_len*32.
static bool jsonArrayHexToSiblings32(const QString& json_array_str, QByteArray& out_bytes, uintptr_t& out_len) {
    QJsonDocument doc = QJsonDocument::fromJson(json_array_str.toUtf8());
    if (!doc.isArray()) {
        return false;
    }
    const QJsonArray arr = doc.array();
    out_len = static_cast<uintptr_t>(arr.size());
    out_bytes.clear();
    out_bytes.reserve(static_cast<int>(out_len * 32));

    for (const QJsonValue& v : arr) {
        if (!v.isString()) {
            return false;
        }
        QByteArray bytes;
        if (!hexToBytes(v.toString(), bytes, 32)) {
            return false;
        }
        out_bytes.append(bytes);
    }
    return true;
}

LogosExecutionZoneWalletModule::LogosExecutionZoneWalletModule() = default;

LogosExecutionZoneWalletModule::~LogosExecutionZoneWalletModule() {
    if (walletHandle) {
        wallet_ffi_destroy(walletHandle);
        walletHandle = nullptr;
    }
}

// === Plugin Interface ===

QString LogosExecutionZoneWalletModule::name() const {
    return "liblogos_execution_zone_wallet_module";
}

QString LogosExecutionZoneWalletModule::version() const {
    return "1.0.0";
}

// === Logos Core ===

void LogosExecutionZoneWalletModule::initLogos(LogosAPI* logosApiInstance) {
    logosAPI = logosApiInstance;
}

// === Account Management ===

QString LogosExecutionZoneWalletModule::create_account_public() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_public(walletHandle, &id);
    if (error != SUCCESS) {
        qWarning() << "create_account_public: wallet FFI error" << error;
        return {};
    }
    return bytes32ToHex(id);
}

QString LogosExecutionZoneWalletModule::create_account_private() {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_private(walletHandle, &id);
    if (error != SUCCESS) {
        qWarning() << "create_account_private: wallet FFI error" << error;
        return {};
    }
    return bytes32ToHex(id);
}

QJsonArray LogosExecutionZoneWalletModule::list_accounts() {
    FfiAccountList list{};
    const WalletFfiError error = wallet_ffi_list_accounts(walletHandle, &list);
    if (error != SUCCESS) {
        qWarning() << "list_accounts: wallet FFI error" << error;
        return {};
    }
    QJsonArray result;
    for (uintptr_t i = 0; i < list.count; ++i) {
        result.append(ffiAccountListEntryToJson(list.entries[i]));
    }
    wallet_ffi_free_account_list(&list);
    return result;
}

// === Account Queries ===

QString LogosExecutionZoneWalletModule::get_balance(const QString& account_id_hex, const bool is_public) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "get_balance: invalid account_id_hex";
        return {};
    }

    uint8_t balance[16] = {0};
    const WalletFfiError error = wallet_ffi_get_balance(walletHandle, &id, is_public, &balance);
    if (error != SUCCESS) {
        qWarning() << "get_balance: wallet FFI error" << error;
        return {};
    }
    return bytesToHex(balance, 16);
}

QString LogosExecutionZoneWalletModule::get_account_public(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "get_account_public: invalid account_id_hex";
        return {};
    }
    FfiAccount account{};
    const WalletFfiError error = wallet_ffi_get_account_public(walletHandle, &id, &account);
    if (error != SUCCESS) {
        qWarning() << "get_account_public: wallet FFI error" << error;
        return {};
    }
    QString result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

QString LogosExecutionZoneWalletModule::get_account_private(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "get_account_private: invalid account_id_hex";
        return {};
    }
    FfiAccount account{};
    const WalletFfiError error = wallet_ffi_get_account_private(walletHandle, &id, &account);
    if (error != SUCCESS) {
        qWarning() << "get_account_private: wallet FFI error" << error;
        return {};
    }
    QString result = ffiAccountToJson(account);
    wallet_ffi_free_account_data(&account);
    return result;
}

QString LogosExecutionZoneWalletModule::get_public_account_key(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "get_public_account_key: invalid account_id_hex";
        return {};
    }
    FfiPublicAccountKey key{};
    const WalletFfiError error = wallet_ffi_get_public_account_key(walletHandle, &id, &key);
    if (error != SUCCESS) {
        qWarning() << "get_public_account_key: wallet FFI error" << error;
        return {};
    }
    return bytes32ToHex(key.public_key);
}

QString LogosExecutionZoneWalletModule::get_private_account_keys(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "get_private_account_keys: invalid account_id_hex";
        return {};
    }
    FfiPrivateAccountKeys keys{};
    const WalletFfiError error = wallet_ffi_get_private_account_keys(walletHandle, &id, &keys);
    if (error != SUCCESS) {
        qWarning() << "get_private_account_keys: wallet FFI error" << error;
        return {};
    }
    QString result = ffiPrivateAccountKeysToJson(keys);
    wallet_ffi_free_private_account_keys(&keys);
    return result;
}

// === Account Encoding ===

QString LogosExecutionZoneWalletModule::account_id_to_base58(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return {};
    }

    char* str = wallet_ffi_account_id_to_base58(&id);
    if (!str) {
        return {};
    }

    QString result = QString::fromUtf8(str);
    wallet_ffi_free_string(str);
    return result;
}

QString LogosExecutionZoneWalletModule::account_id_from_base58(const QString& base58_str) {
    FfiBytes32 id{};
    const QByteArray utf8 = base58_str.toUtf8();
    const WalletFfiError error = wallet_ffi_account_id_from_base58(utf8.constData(), &id);
    if (error != SUCCESS) {
        qWarning() << "account_id_from_base58: wallet FFI error" << error;
        return {};
    }
    return bytes32ToHex(id);
}

// === Blockchain Synchronisation ===

WalletFfiError LogosExecutionZoneWalletModule::sync_to_block(const uint64_t block_id) {
    return wallet_ffi_sync_to_block(walletHandle, block_id);
}

uint64_t LogosExecutionZoneWalletModule::get_last_synced_block() {
    uint64_t block_id = 0;
    const WalletFfiError error = wallet_ffi_get_last_synced_block(walletHandle, &block_id);
    if (error != SUCCESS) {
        qWarning() << "get_last_synced_block: wallet FFI error" << error;
        return 0;
    }
    return block_id;
}

uint64_t LogosExecutionZoneWalletModule::get_current_block_height() {
    uint64_t block_height = 0;
    const WalletFfiError error = wallet_ffi_get_current_block_height(walletHandle, &block_height);
    if (error != SUCCESS) {
        qWarning() << "get_current_block_height: wallet FFI error" << error;
        return 0;
    }
    return block_height;
}

// === Pinata claiming ===

QString LogosExecutionZoneWalletModule::claim_pinata(
    const QString& pinata_account_id_hex,
    const QString& winner_account_id_hex,
    const QString& solution_le16_hex
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        qWarning() << "claim_pinata: invalid account id hex";
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        qWarning() << "claim_pinata: solution_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_claim_pinata(walletHandle, &pinataId, &winnerId, &solution, &result);
    if (error != SUCCESS) {
        qWarning() << "claim_pinata: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::claim_pinata_private_owned_already_initialized(
    const QString& pinata_account_id_hex,
    const QString& winner_account_id_hex,
    const QString& solution_le16_hex,
    uint64_t winner_proof_index,
    const QString& winner_proof_siblings_json
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        qWarning() << "claim_pinata_private_owned_already_initialized: invalid account id hex";
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        qWarning() << "claim_pinata_private_owned_already_initialized: solution_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }

    QByteArray siblings_bytes;
    uintptr_t siblings_len = 0;
    if (!jsonArrayHexToSiblings32(winner_proof_siblings_json, siblings_bytes, siblings_len)) {
        qWarning() << "claim_pinata_private_owned_already_initialized: failed to parse winner_proof_siblings_json";
        return {};
    }

    const uint8_t (*siblings_ptr)[32] = nullptr;
    if (siblings_len > 0) {
        siblings_ptr = reinterpret_cast<const uint8_t (*)[32]>(siblings_bytes.constData());
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
        qWarning() << "claim_pinata_private_owned_already_initialized: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::claim_pinata_private_owned_not_initialized(
    const QString& pinata_account_id_hex,
    const QString& winner_account_id_hex,
    const QString& solution_le16_hex
) {
    FfiBytes32 pinataId{}, winnerId{};
    if (!hexToBytes32(pinata_account_id_hex, &pinataId) || !hexToBytes32(winner_account_id_hex, &winnerId)) {
        qWarning() << "claim_pinata_private_owned_not_initialized: invalid account id hex";
        return {};
    }
    uint8_t solution[16];
    if (!hexToU128(solution_le16_hex, &solution)) {
        qWarning() << "claim_pinata_private_owned_not_initialized: solution_le16_hex must be 32 hex characters (16 bytes)";
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
        qWarning() << "claim_pinata_private_owned_not_initialized: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

// === Operations ===

QString LogosExecutionZoneWalletModule::transfer_public(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        qWarning() << "transfer_public: invalid account id hex";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_public: amount_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_public(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        qWarning() << "transfer_public: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::transfer_shielded(
    const QString& from_hex,
    const QString& to_keys_json,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        qWarning() << "transfer_shielded: invalid from account id hex";
        return {};
    }

    FfiPrivateAccountKeys toKeys{};
    if (!jsonToFfiPrivateAccountKeys(to_keys_json, &toKeys)) {
        qWarning() << "transfer_shielded: failed to parse to_keys_json";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)";
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_shielded(walletHandle, &fromId, &toKeys, &amount, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
        qWarning() << "transfer_shielded: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::transfer_deshielded(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        qWarning() << "transfer_deshielded: invalid account id hex";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_deshielded: amount_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_deshielded(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        qWarning() << "transfer_deshielded: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::transfer_private(
    const QString& from_hex,
    const QString& to_keys_json,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        qWarning() << "transfer_private: invalid from account id hex";
        return {};
    }

    FfiPrivateAccountKeys toKeys{};
    if (!jsonToFfiPrivateAccountKeys(to_keys_json, &toKeys)) {
        qWarning() << "transfer_private: failed to parse to_keys_json";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)";
        free(const_cast<uint8_t*>(toKeys.viewing_public_key));
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_private(walletHandle, &fromId, &toKeys, &amount, &result);
    free(const_cast<uint8_t*>(toKeys.viewing_public_key));
    if (error != SUCCESS) {
        qWarning() << "transfer_private: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::transfer_shielded_owned(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        qWarning() << "transfer_shielded_owned: invalid account id hex";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_shielded_owned: amount_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_shielded_owned(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        qWarning() << "transfer_shielded_owned: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::transfer_private_owned(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        qWarning() << "transfer_private_owned: invalid account id hex";
        return {};
    }

    uint8_t amount[16];
    if (!hexToU128(amount_le16_hex, &amount)) {
        qWarning() << "transfer_private_owned: amount_le16_hex must be 32 hex characters (16 bytes)";
        return {};
    }

    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_transfer_private_owned(walletHandle, &fromId, &toId, &amount, &result);
    if (error != SUCCESS) {
        qWarning() << "transfer_private_owned: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::register_public_account(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "register_public_account: invalid account_id_hex";
        return {};
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_register_public_account(walletHandle, &id, &result);
    if (error != SUCCESS) {
        qWarning() << "register_public_account: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

QString LogosExecutionZoneWalletModule::register_private_account(const QString& account_id_hex) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        qWarning() << "register_private_account: invalid account_id_hex";
        return {};
    }
    FfiTransferResult result{};
    const WalletFfiError error = wallet_ffi_register_private_account(walletHandle, &id, &result);
    if (error != SUCCESS) {
        qWarning() << "register_private_account: wallet FFI error" << error;
        return {};
    }
    QString resultJson = ffiTransferResultToJson(result);
    wallet_ffi_free_transfer_result(&result);
    return resultJson;
}

// === Wallet Lifecycle ===

WalletFfiError LogosExecutionZoneWalletModule::create_new(
    const QString& config_path,
    const QString& storage_path,
    const QString& password
) {
    if (walletHandle) {
        qWarning() << "create_new: wallet is already open";
        return INTERNAL_ERROR;
    }

    const QByteArray config_utf8 = config_path.toUtf8();
    const QByteArray storage_utf8 = storage_path.toUtf8();
    const QByteArray password_utf8 = password.toUtf8();

    walletHandle = wallet_ffi_create_new(config_utf8.constData(), storage_utf8.constData(), password_utf8.constData());
    if (!walletHandle) {
        qWarning() << "create_new: wallet_ffi_create_new returned null";
        return INTERNAL_ERROR;
    }

    return SUCCESS;
}

WalletFfiError LogosExecutionZoneWalletModule::open(const QString& config_path, const QString& storage_path) {
    if (walletHandle) {
        qWarning() << "open: wallet is already open";
        return INTERNAL_ERROR;
    }

    const QByteArray config_utf8 = config_path.toUtf8();
    const QByteArray storage_utf8 = storage_path.toUtf8();

    walletHandle = wallet_ffi_open(config_utf8.constData(), storage_utf8.constData());
    if (!walletHandle) {
        qWarning() << "open: wallet_ffi_open returned null";
        return INTERNAL_ERROR;
    }

    return SUCCESS;
}

WalletFfiError LogosExecutionZoneWalletModule::save() {
    return wallet_ffi_save(walletHandle);
}

// === Configuration ===

QString LogosExecutionZoneWalletModule::get_sequencer_addr() {
    char* addr = wallet_ffi_get_sequencer_addr(walletHandle);
    if (!addr) {
        return {};
    }

    QString result = QString::fromUtf8(addr);
    wallet_ffi_free_string(addr);
    return result;
}
