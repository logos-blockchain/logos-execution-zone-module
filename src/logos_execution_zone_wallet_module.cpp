#include "logos_execution_zone_wallet_module.h"

#include <QtCore/QDebug>

LogosExecutionZoneWalletModule::LogosExecutionZoneWalletModule() = default;
LogosExecutionZoneWalletModule::~LogosExecutionZoneWalletModule() = default;

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

WalletFfiError LogosExecutionZoneWalletModule::create_account_public(WalletHandle* handle, FfiBytes32* out_account_id) {
    return wallet_ffi_create_account_public(handle, out_account_id);
}

WalletFfiError LogosExecutionZoneWalletModule::create_account_private(
    WalletHandle* handle,
    FfiBytes32* out_account_id
) {
    return wallet_ffi_create_account_private(handle, out_account_id);
}

WalletFfiError LogosExecutionZoneWalletModule::list_accounts(WalletHandle* handle, FfiAccountList* out_list) {
    return wallet_ffi_list_accounts(handle, out_list);
}

// === Account Queries ===

WalletFfiError LogosExecutionZoneWalletModule::get_balance(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    const bool is_public,
    QByteArray* out_balance_le16
) {
    uint8_t balance[16] = {0};

    const WalletFfiError err = wallet_ffi_get_balance(handle, account_id, is_public, &balance);
    if (err == SUCCESS && out_balance_le16) {
        *out_balance_le16 = QByteArray(reinterpret_cast<const char*>(balance), 16);
    }

    return err;
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_public(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiAccount* out_account
) {
    return wallet_ffi_get_account_public(handle, account_id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_private(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiAccount* out_account
) {
    return wallet_ffi_get_account_private(handle, account_id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_public_account_key(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiPublicAccountKey* out_public_key
) {
    return wallet_ffi_get_public_account_key(handle, account_id, out_public_key);
}

WalletFfiError LogosExecutionZoneWalletModule::get_private_account_keys(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiPrivateAccountKeys* out_keys
) {
    return wallet_ffi_get_private_account_keys(handle, account_id, out_keys);
}

// === Account Encoding ===

QString LogosExecutionZoneWalletModule::account_id_to_base58(const FfiBytes32* account_id) {
    char* str = wallet_ffi_account_id_to_base58(account_id);
    if (!str) {
        return {};
    }

    QString result = QString::fromUtf8(str);
    wallet_ffi_free_string(str);
    return result;
}

WalletFfiError LogosExecutionZoneWalletModule::account_id_from_base58(
    const QString& base58_str,
    FfiBytes32* out_account_id
) {
    const QByteArray utf8 = base58_str.toUtf8();
    return wallet_ffi_account_id_from_base58(utf8.constData(), out_account_id);
}

// === Blockchain Synchronisation ===

WalletFfiError LogosExecutionZoneWalletModule::sync_to_block(WalletHandle* handle, const uint64_t block_id) {
    return wallet_ffi_sync_to_block(handle, block_id);
}

WalletFfiError LogosExecutionZoneWalletModule::get_last_synced_block(WalletHandle* handle, uint64_t* out_block_id) {
    return wallet_ffi_get_last_synced_block(handle, out_block_id);
}

WalletFfiError LogosExecutionZoneWalletModule::get_current_block_height(
    WalletHandle* handle,
    uint64_t* out_block_height
) {
    return wallet_ffi_get_current_block_height(handle, out_block_height);
}

// === Operations ===

WalletFfiError LogosExecutionZoneWalletModule::transfer_public(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiBytes32* to,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_public: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_public(handle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiPrivateAccountKeys* to_keys,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_shielded: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_shielded(handle, from, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_deshielded(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiBytes32* to,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_deshielded: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_deshielded(handle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiPrivateAccountKeys* to_keys,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_private: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_private(handle, from, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded_owned(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiBytes32* to,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_shielded_owned: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_shielded_owned(handle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private_owned(
    WalletHandle* handle,
    const FfiBytes32* from,
    const FfiBytes32* to,
    const QByteArray& amount_le16,
    FfiTransferResult* out_result
) {
    if (amount_le16.size() != 16) {
        qWarning() << "transfer_private_owned: amount_le16 must be 16 bytes";
        return SERIALIZATION_ERROR;
    }

    uint8_t amount[16];
    memcpy(amount, amount_le16.constData(), 16);

    return wallet_ffi_transfer_private_owned(handle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_public_account(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiTransferResult* out_result
) {
    return wallet_ffi_register_public_account(handle, account_id, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_private_account(
    WalletHandle* handle,
    const FfiBytes32* account_id,
    FfiTransferResult* out_result
) {
    return wallet_ffi_register_private_account(handle, account_id, out_result);
}

// === Wallet Lifecycle ===

WalletHandle* LogosExecutionZoneWalletModule::create_new(
    const QString& config_path,
    const QString& storage_path,
    const QString& password
) {
    const QByteArray config_utf8 = config_path.toUtf8();
    const QByteArray storage_utf8 = storage_path.toUtf8();
    const QByteArray password_utf8 = password.toUtf8();

    return wallet_ffi_create_new(config_utf8.constData(), storage_utf8.constData(), password_utf8.constData());
}

WalletHandle* LogosExecutionZoneWalletModule::open(const QString& config_path, const QString& storage_path) {
    const QByteArray config_utf8 = config_path.toUtf8();
    const QByteArray storage_utf8 = storage_path.toUtf8();

    return wallet_ffi_open(config_utf8.constData(), storage_utf8.constData());
}

WalletFfiError LogosExecutionZoneWalletModule::save(WalletHandle* handle) {
    return wallet_ffi_save(handle);
}

// === Configuration ===

QString LogosExecutionZoneWalletModule::get_sequencer_addr(WalletHandle* handle) {
    char* addr = wallet_ffi_get_sequencer_addr(handle);
    if (!addr) {
        return {};
    }

    QString result = QString::fromUtf8(addr);
    wallet_ffi_free_string(addr);
    return result;
}
