// Stub header for wallet_ffi — provides the same declarations as the real
// lssa-generated header so that logos_execution_zone_wallet_module sources
// compile in unit tests (the real library is NOT linked; mocks supply symbols).
//
// Only the subset of the FFI surface used by the module is declared here.

#ifndef WALLET_FFI_H
#define WALLET_FFI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes returned by most wallet_ffi_* functions (0 == SUCCESS).
typedef enum WalletFfiError {
    SUCCESS = 0,
    INTERNAL_ERROR = 1,
    INVALID_INPUT = 2,
    NOT_FOUND = 3,
} WalletFfiError;

// Opaque wallet handle.
typedef struct WalletHandle WalletHandle;

// 32-byte value (account id, key, hash).
typedef struct FfiBytes32 {
    uint8_t data[32];
} FfiBytes32;

// 16-byte value (balance / nonce, little-endian u128).
typedef struct FfiBytes16 {
    uint8_t data[16];
} FfiBytes16;

// Full account record.
typedef struct FfiAccount {
    FfiBytes32 program_owner;
    FfiBytes16 balance;
    FfiBytes16 nonce;
    uint8_t* data;
    uintptr_t data_len;
} FfiAccount;

// One entry in a listing of accounts.
typedef struct FfiAccountListEntry {
    FfiBytes32 account_id;
    bool is_public;
} FfiAccountListEntry;

// A list of accounts (heap-owned by the library).
typedef struct FfiAccountList {
    FfiAccountListEntry* entries;
    uintptr_t count;
} FfiAccountList;

// Public account key.
typedef struct FfiPublicAccountKey {
    FfiBytes32 public_key;
} FfiPublicAccountKey;

// Private account keys (viewing key is heap-owned).
typedef struct FfiPrivateAccountKeys {
    FfiBytes32 nullifier_public_key;
    uint8_t* viewing_public_key;
    uintptr_t viewing_public_key_len;
} FfiPrivateAccountKeys;

// Result of a transfer / claim / register operation.
typedef struct FfiTransferResult {
    bool success;
    char* tx_hash;
} FfiTransferResult;

// === Lifecycle ===

WalletHandle* wallet_ffi_create_new(const char* config_path, const char* storage_path, const char* password);
WalletHandle* wallet_ffi_open(const char* config_path, const char* storage_path);
int wallet_ffi_save(WalletHandle* handle);
void wallet_ffi_destroy(WalletHandle* handle);

// === Account management ===

WalletFfiError wallet_ffi_create_account_public(WalletHandle* handle, FfiBytes32* out_id);
WalletFfiError wallet_ffi_create_account_private(WalletHandle* handle, FfiBytes32* out_id);
WalletFfiError wallet_ffi_list_accounts(WalletHandle* handle, FfiAccountList* out_list);
void wallet_ffi_free_account_list(FfiAccountList* list);

// === Account queries ===

WalletFfiError wallet_ffi_get_balance(WalletHandle* handle, const FfiBytes32* account_id, bool is_public, uint8_t (*out_balance)[16]);
WalletFfiError wallet_ffi_get_account_public(WalletHandle* handle, const FfiBytes32* account_id, FfiAccount* out_account);
WalletFfiError wallet_ffi_get_account_private(WalletHandle* handle, const FfiBytes32* account_id, FfiAccount* out_account);
void wallet_ffi_free_account_data(FfiAccount* account);
WalletFfiError wallet_ffi_get_public_account_key(WalletHandle* handle, const FfiBytes32* account_id, FfiPublicAccountKey* out_key);
WalletFfiError wallet_ffi_get_private_account_keys(WalletHandle* handle, const FfiBytes32* account_id, FfiPrivateAccountKeys* out_keys);
void wallet_ffi_free_private_account_keys(FfiPrivateAccountKeys* keys);

// === Account encoding ===

char* wallet_ffi_account_id_to_base58(const FfiBytes32* account_id);
WalletFfiError wallet_ffi_account_id_from_base58(const char* base58, FfiBytes32* out_id);
void wallet_ffi_free_string(char* s);

// === Blockchain synchronisation ===

int wallet_ffi_sync_to_block(WalletHandle* handle, uint64_t block_id);
WalletFfiError wallet_ffi_get_last_synced_block(WalletHandle* handle, uint64_t* out_block_id);
WalletFfiError wallet_ffi_get_current_block_height(WalletHandle* handle, uint64_t* out_block_height);

// === Pinata claiming ===

WalletFfiError wallet_ffi_claim_pinata(
    WalletHandle* handle,
    const FfiBytes32* pinata_account_id,
    const FfiBytes32* winner_account_id,
    const uint8_t (*solution)[16],
    FfiTransferResult* out_result);

WalletFfiError wallet_ffi_claim_pinata_private_owned_already_initialized(
    WalletHandle* handle,
    const FfiBytes32* pinata_account_id,
    const FfiBytes32* winner_account_id,
    const uint8_t (*solution)[16],
    uintptr_t winner_proof_index,
    const uint8_t (*winner_proof_siblings)[32],
    uintptr_t winner_proof_siblings_len,
    FfiTransferResult* out_result);

WalletFfiError wallet_ffi_claim_pinata_private_owned_not_initialized(
    WalletHandle* handle,
    const FfiBytes32* pinata_account_id,
    const FfiBytes32* winner_account_id,
    const uint8_t (*solution)[16],
    FfiTransferResult* out_result);

// === Transfers / registration ===

WalletFfiError wallet_ffi_transfer_public(
    WalletHandle* handle, const FfiBytes32* from, const FfiBytes32* to,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);
WalletFfiError wallet_ffi_transfer_shielded(
    WalletHandle* handle, const FfiBytes32* from, const FfiPrivateAccountKeys* to_keys,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);
WalletFfiError wallet_ffi_transfer_deshielded(
    WalletHandle* handle, const FfiBytes32* from, const FfiBytes32* to,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);
WalletFfiError wallet_ffi_transfer_private(
    WalletHandle* handle, const FfiBytes32* from, const FfiPrivateAccountKeys* to_keys,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);
WalletFfiError wallet_ffi_transfer_shielded_owned(
    WalletHandle* handle, const FfiBytes32* from, const FfiBytes32* to,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);
WalletFfiError wallet_ffi_transfer_private_owned(
    WalletHandle* handle, const FfiBytes32* from, const FfiBytes32* to,
    const uint8_t (*amount)[16], FfiTransferResult* out_result);

WalletFfiError wallet_ffi_register_public_account(WalletHandle* handle, const FfiBytes32* account_id, FfiTransferResult* out_result);
WalletFfiError wallet_ffi_register_private_account(WalletHandle* handle, const FfiBytes32* account_id, FfiTransferResult* out_result);

void wallet_ffi_free_transfer_result(FfiTransferResult* result);

// === Configuration ===

char* wallet_ffi_get_sequencer_addr(WalletHandle* handle);

#ifdef __cplusplus
}
#endif

#endif // WALLET_FFI_H
