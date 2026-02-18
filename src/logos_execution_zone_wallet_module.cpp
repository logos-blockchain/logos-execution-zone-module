#include "logos_execution_zone_wallet_module.h"

#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QVariantMap>

static QString bytesToHex(const uint8_t* data, const size_t length) {
    const QByteArray bytearray(reinterpret_cast<const char*>(data), static_cast<int>(length));
    return QString::fromLatin1(bytearray.toHex());
}

static bool hexToBytes(const QString& hex, QByteArray& output_bytes, int expectedLength = -1) {
    QString trimmed_hex = hex.trimmed();
    if (trimmed_hex.startsWith("0x", Qt::CaseInsensitive)) trimmed_hex = trimmed_hex.mid(2);
    if (trimmed_hex.size() % 2 != 0) return false;
    const QByteArray decoded = QByteArray::fromHex(trimmed_hex.toLatin1());
    if (expectedLength != -1 && decoded.size() != expectedLength) return false;
    output_bytes = decoded;
    return true;
}

static bool hexToU128(const QString& hex, uint8_t (*output)[16]) {
    QByteArray buffer;
    if (!hexToBytes(hex, buffer, 16)) return false;
    memcpy(output, buffer.constData(), 16);
    return true;
}

static QString bytes32ToHex(const FfiBytes32& bytes) {
    return bytesToHex(bytes.data, 32);
}

static bool hexToBytes32(const QString& hex, FfiBytes32* output_bytes) {
    if (output_bytes == nullptr) return false;
    QByteArray buffer;
    if (!hexToBytes(hex, buffer, 32)) return false;
    memcpy(output_bytes->data, buffer.constData(), 32);
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
    return "liblogos-execution-zone-wallet-module";
}

QString LogosExecutionZoneWalletModule::version() const {
    return "1.0.0";
}

// === Logos Core ===

void LogosExecutionZoneWalletModule::initLogos(LogosAPI* logosApiInstance) {
    logosApi = logosApiInstance;
}

// === Account Management ===

WalletFfiError LogosExecutionZoneWalletModule::create_account_public(QString& out_account_id_hex) {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_public(walletHandle, &id);
    if (error == SUCCESS) {
        out_account_id_hex = bytes32ToHex(id);
    }
    return error;
}

WalletFfiError LogosExecutionZoneWalletModule::create_account_private(QString& out_account_id_hex) {
    FfiBytes32 id{};
    const WalletFfiError error = wallet_ffi_create_account_private(walletHandle, &id);
    if (error == SUCCESS) {
        out_account_id_hex = bytes32ToHex(id);
    }
    return error;
}

WalletFfiError LogosExecutionZoneWalletModule::list_accounts(FfiAccountList* out_list) {
    return wallet_ffi_list_accounts(walletHandle, out_list);
}

// === Account Queries ===

WalletFfiError LogosExecutionZoneWalletModule::get_balance(
    const QString& account_id_hex,
    const bool is_public,
    QString& out_balance_le16_hex
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }

    uint8_t balance[16] = {0};
    const WalletFfiError error = wallet_ffi_get_balance(walletHandle, &id, is_public, &balance);
    if (error == SUCCESS) {
        out_balance_le16_hex = bytesToHex(balance, 16);
    }
    return error;
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_public(
    const QString& account_id_hex,
    FfiAccount* out_account
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    return wallet_ffi_get_account_public(walletHandle, &id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_private(
    const QString& account_id_hex,
    FfiAccount* out_account
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    return wallet_ffi_get_account_private(walletHandle, &id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_public_account_key(
    const QString& account_id_hex,
    QString& out_public_key_hex
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    FfiPublicAccountKey key{};
    const WalletFfiError error = wallet_ffi_get_public_account_key(walletHandle, &id, &key);
    if (error == SUCCESS) {
        out_public_key_hex = bytes32ToHex(key.public_key);
    }
    return error;
}

WalletFfiError LogosExecutionZoneWalletModule::get_private_account_keys(
    const QString& account_id_hex,
    FfiPrivateAccountKeys* out_keys
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    return wallet_ffi_get_private_account_keys(walletHandle, &id, out_keys);
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

WalletFfiError LogosExecutionZoneWalletModule::account_id_from_base58(
    const QString& base58_str,
    QString& out_account_id_hex
) {
    FfiBytes32 id{};
    const QByteArray utf8 = base58_str.toUtf8();
    const WalletFfiError error = wallet_ffi_account_id_from_base58(utf8.constData(), &id);
    if (error == SUCCESS) {
        out_account_id_hex = bytes32ToHex(id);
    }
    return error;
}

// === Blockchain Synchronisation ===

WalletFfiError LogosExecutionZoneWalletModule::sync_to_block(const uint64_t block_id) {
    return wallet_ffi_sync_to_block(walletHandle, block_id);
}

WalletFfiError LogosExecutionZoneWalletModule::get_last_synced_block(uint64_t* out_block_id) {
    return wallet_ffi_get_last_synced_block(walletHandle, out_block_id);
}

WalletFfiError LogosExecutionZoneWalletModule::get_current_block_height(uint64_t* out_block_height) {
    return wallet_ffi_get_current_block_height(walletHandle, out_block_height);
}

// === Operations ===

WalletFfiError LogosExecutionZoneWalletModule::transfer_public(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_public: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_public(walletHandle, &fromId, &toId, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded(
    const QString& from_hex,
    const FfiPrivateAccountKeys* to_keys,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_shielded: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_shielded(walletHandle, &fromId, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_deshielded(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_deshielded: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_deshielded(walletHandle, &fromId, &toId, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private(
    const QString& from_hex,
    const FfiPrivateAccountKeys* to_keys,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{};
    if (!hexToBytes32(from_hex, &fromId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_private: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_private(walletHandle, &fromId, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded_owned(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_shielded_owned: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_shielded_owned(walletHandle, &fromId, &toId, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private_owned(
    const QString& from_hex,
    const QString& to_hex,
    const QString& amount_le16_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 fromId{}, toId{};
    if (!hexToBytes32(from_hex, &fromId) || !hexToBytes32(to_hex, &toId)) {
        return INVALID_ACCOUNT_ID;
    }

    QByteArray amount_byte_array;
    if (!hexToBytes(amount_le16_hex, amount_byte_array, 16)) {
        qWarning() << "transfer_private_owned: amount_le16_hex must be 32 hex characters (16 bytes)";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_byte_array.constData(), 16);

    return wallet_ffi_transfer_private_owned(walletHandle, &fromId, &toId, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_public_account(
    const QString& account_id_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    return wallet_ffi_register_public_account(walletHandle, &id, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_private_account(
    const QString& account_id_hex,
    FfiTransferResult* out_result
) {
    FfiBytes32 id{};
    if (!hexToBytes32(account_id_hex, &id)) {
        return INVALID_ACCOUNT_ID;
    }
    return wallet_ffi_register_private_account(walletHandle, &id, out_result);
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
