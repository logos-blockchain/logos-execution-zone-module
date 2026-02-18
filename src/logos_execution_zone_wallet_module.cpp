#include "logos_execution_zone_wallet_module.h"

#include <QtCore/QDebug>

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

WalletFfiError LogosExecutionZoneWalletModule::create_account_public(FfiBytes32* out_account_id) {
    return wallet_ffi_create_account_public(walletHandle, out_account_id);
}

WalletFfiError LogosExecutionZoneWalletModule::create_account_private(FfiBytes32* out_account_id) {
    return wallet_ffi_create_account_private(walletHandle, out_account_id);
}

WalletFfiError LogosExecutionZoneWalletModule::list_accounts(FfiAccountList* out_list) {
    return wallet_ffi_list_accounts(walletHandle, out_list);
}

// === Account Queries ===

WalletFfiError LogosExecutionZoneWalletModule::get_balance(
    const FfiBytes32* account_id,
    const bool is_public,
    QByteArray* out_balance_le16
) {
    uint8_t balance[16] = {0};

    const WalletFfiError err = wallet_ffi_get_balance(walletHandle, account_id, is_public, &balance);
    if (err == SUCCESS && out_balance_le16) {
        *out_balance_le16 = QByteArray(reinterpret_cast<const char*>(balance), 16);
    }

    return err;
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_public(
    const FfiBytes32* account_id,
    FfiAccount* out_account
) {
    return wallet_ffi_get_account_public(walletHandle, account_id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_account_private(
    const FfiBytes32* account_id,
    FfiAccount* out_account
) {
    return wallet_ffi_get_account_private(walletHandle, account_id, out_account);
}

WalletFfiError LogosExecutionZoneWalletModule::get_public_account_key(
    const FfiBytes32* account_id,
    FfiPublicAccountKey* out_public_key
) {
    return wallet_ffi_get_public_account_key(walletHandle, account_id, out_public_key);
}

WalletFfiError LogosExecutionZoneWalletModule::get_private_account_keys(
    const FfiBytes32* account_id,
    FfiPrivateAccountKeys* out_keys
) {
    return wallet_ffi_get_private_account_keys(walletHandle, account_id, out_keys);
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

    return wallet_ffi_transfer_public(walletHandle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded(
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

    return wallet_ffi_transfer_shielded(walletHandle, from, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_deshielded(
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

    return wallet_ffi_transfer_deshielded(walletHandle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private(
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

    return wallet_ffi_transfer_private(walletHandle, from, to_keys, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_shielded_owned(
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

    return wallet_ffi_transfer_shielded_owned(walletHandle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::transfer_private_owned(
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

    return wallet_ffi_transfer_private_owned(walletHandle, from, to, &amount, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_public_account(
    const FfiBytes32* account_id,
    FfiTransferResult* out_result
) {
    return wallet_ffi_register_public_account(walletHandle, account_id, out_result);
}

WalletFfiError LogosExecutionZoneWalletModule::register_private_account(
    const FfiBytes32* account_id,
    FfiTransferResult* out_result
) {
    return wallet_ffi_register_private_account(walletHandle, account_id, out_result);
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
