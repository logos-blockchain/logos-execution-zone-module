// Mock implementation of the wallet_ffi C functions.
// Replaces the real lssa wallet library at link time during unit tests.
// Return codes and out-parameter contents are controlled via LogosCMockStore.
//
// Conventions:
//  - Functions returning WalletFfiError use LOGOS_CMOCK_RETURN(int, "<fn>"); an
//    unset mock defaults to 0 (SUCCESS), so the happy path needs no setup.
//  - Out-parameters are filled with deterministic bytes only on success so tests
//    can assert on the resulting hex/JSON.

#include <logos_clib_mock.h>

extern "C" {
#include <wallet_ffi.h>
}

#include <cstdlib>
#include <cstring>

namespace {

// A single non-null sentinel handle handed back by create_new / open.
char g_fakeWallet = 0;

// Backing storage for list_accounts (returned by pointer to the caller).
FfiAccountListEntry g_accountEntries[8];

// Fill a transfer result based on the mocked error code for `key`.
WalletFfiError fillTransferResult(const char* key, FfiTransferResult* out_result) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (out_result) {
        out_result->success = (err == 0);
        if (err == 0) {
            const char* tx = LogosCMockStore::instance().getReturnString("transfer_tx_hash");
            // getReturnString yields "" (non-null) when unset; fall back to a default.
            out_result->tx_hash = strdup((tx && *tx) ? tx : "0xmocktxhash");
        } else {
            out_result->tx_hash = nullptr;
        }
    }
    return static_cast<WalletFfiError>(err);
}

} // namespace

extern "C" {

// === Lifecycle ===

WalletHandle* wallet_ffi_create_new(const char*, const char*, const char*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_create_new");
    const int ok = LOGOS_CMOCK_RETURN(int, "wallet_ffi_create_new");
    return ok ? reinterpret_cast<WalletHandle*>(&g_fakeWallet) : nullptr;
}

WalletHandle* wallet_ffi_open(const char*, const char*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_open");
    const int ok = LOGOS_CMOCK_RETURN(int, "wallet_ffi_open");
    return ok ? reinterpret_cast<WalletHandle*>(&g_fakeWallet) : nullptr;
}

int wallet_ffi_save(WalletHandle*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_save");
    return LOGOS_CMOCK_RETURN(int, "wallet_ffi_save");
}

void wallet_ffi_destroy(WalletHandle*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_destroy");
}

// === Account management ===

WalletFfiError wallet_ffi_create_account_public(WalletHandle*, FfiBytes32* out_id) {
    LOGOS_CMOCK_RECORD("wallet_ffi_create_account_public");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_create_account_public");
    if (err == 0 && out_id) {
        memset(out_id->data, 0xAB, sizeof(out_id->data));
    }
    return static_cast<WalletFfiError>(err);
}

WalletFfiError wallet_ffi_create_account_private(WalletHandle*, FfiBytes32* out_id) {
    LOGOS_CMOCK_RECORD("wallet_ffi_create_account_private");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_create_account_private");
    if (err == 0 && out_id) {
        memset(out_id->data, 0xCD, sizeof(out_id->data));
    }
    return static_cast<WalletFfiError>(err);
}

WalletFfiError wallet_ffi_list_accounts(WalletHandle*, FfiAccountList* out_list) {
    LOGOS_CMOCK_RECORD("wallet_ffi_list_accounts");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_list_accounts");
    if (!out_list) {
        return static_cast<WalletFfiError>(err);
    }
    if (err == 0) {
        int count = LOGOS_CMOCK_RETURN(int, "list_accounts_count");
        if (count < 0) count = 0;
        if (count > 8) count = 8;
        for (int i = 0; i < count; ++i) {
            memset(g_accountEntries[i].account_id.data, 0x10 + i, sizeof(g_accountEntries[i].account_id.data));
            g_accountEntries[i].is_public = (i % 2 == 0);
        }
        out_list->entries = g_accountEntries;
        out_list->count = static_cast<uintptr_t>(count);
    } else {
        out_list->entries = nullptr;
        out_list->count = 0;
    }
    return static_cast<WalletFfiError>(err);
}

void wallet_ffi_free_account_list(FfiAccountList* list) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_account_list");
    if (list) {
        list->entries = nullptr;
        list->count = 0;
    }
}

// === Account queries ===

WalletFfiError wallet_ffi_get_balance(WalletHandle*, const FfiBytes32*, bool, uint8_t (*out_balance)[16]) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_balance");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_get_balance");
    if (err == 0 && out_balance) {
        const uint64_t value = static_cast<uint64_t>(LOGOS_CMOCK_RETURN(int, "get_balance_value"));
        memset(*out_balance, 0, 16);
        for (int i = 0; i < 8; ++i) {
            (*out_balance)[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
        }
    }
    return static_cast<WalletFfiError>(err);
}

static WalletFfiError fillProgram(const char* key, FfiProgram *ffi_program) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (err == 0 && ffi_program) {
        memset(const_cast<uint8_t*>(ffi_program->elf_data), 0xAA, 100);
        ffi_program->elf_size = 100;
    }
    return static_cast<WalletFfiError>(err);
}

static WalletFfiError fillAccount(const char* key, FfiAccount* out_account) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (err == 0 && out_account) {
        memset(out_account->program_owner.data, 0xAA, sizeof(out_account->program_owner.data));
        memset(out_account->balance.data, 0, sizeof(out_account->balance.data));
        out_account->balance.data[0] = 0x07;
        memset(out_account->nonce.data, 0, sizeof(out_account->nonce.data));
        out_account->nonce.data[0] = 0x01;
        out_account->data = nullptr;
        out_account->data_len = 0;
    }
    return static_cast<WalletFfiError>(err);
}

static WalletFfiError fillPublicAccountIdentity(const char* key, FfiAccountIdentity *out_account_identity) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (err == 0 && out_account_identity) {
        out_account_identity->kind = FfiAccountIdentityKind::PUBLIC;
        memset(out_account_identity->account_id.data, 0xAA, sizeof(out_account_identity->account_id));
        out_account_identity->key_path = nullptr;
        memset(out_account_identity->nullifier_secret_key.data, 0x00, sizeof(out_account_identity->nullifier_secret_key));
        memset(out_account_identity->nullifier_public_key.data, 0x00, sizeof(out_account_identity->nullifier_public_key));
        out_account_identity->viewing_public_key = nullptr;
        out_account_identity->viewing_public_key_len = 0;
        memset(out_account_identity->identifier.data, 0x01, sizeof(out_account_identity->identifier));
    }
    return static_cast<WalletFfiError>(err);
}

static WalletFfiError fillPrivateAccountIdentity(const char* key, FfiAccountIdentity *out_account_identity) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (err == 0 && out_account_identity) {
        out_account_identity->kind = FfiAccountIdentityKind::PRIVATE_OWNED;
        memset(out_account_identity->account_id.data, 0xAB, sizeof(out_account_identity->account_id));
        out_account_identity->key_path = nullptr;
        memset(out_account_identity->nullifier_secret_key.data, 0x11, sizeof(out_account_identity->nullifier_secret_key));
        memset(out_account_identity->nullifier_public_key.data, 0x22, sizeof(out_account_identity->nullifier_public_key));
        out_account_identity->viewing_public_key = nullptr;
        out_account_identity->viewing_public_key_len = 0;
        memset(out_account_identity->identifier.data, 0x01, sizeof(out_account_identity->identifier));
    }
    return static_cast<WalletFfiError>(err);
}

static WalletFfiError fillTransactionResult(const char* key, FfiTransactionResult *out_result) {
    const int err = LogosCMockStore::instance().getReturn<int>(key);
    if (out_result) {
        out_result->success = (err == 0);
        if (err == 0) {
            const char* tx = LogosCMockStore::instance().getReturnString("transaction_tx_hash");
            // getReturnString yields "" (non-null) when unset; fall back to a default.
            out_result->tx_hash = strdup((tx && *tx) ? tx : "0xmocktxhash2");
        } else {
            out_result->tx_hash = nullptr;
        }
        out_result->secrets_data = nullptr;
        out_result->secrets_size = 0; 
    }
    return static_cast<WalletFfiError>(err);
}

WalletFfiError wallet_ffi_get_account_public(WalletHandle*, const FfiBytes32*, FfiAccount* out_account) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_account_public");
    return fillAccount("wallet_ffi_get_account_public", out_account);
}

WalletFfiError wallet_ffi_get_account_private(WalletHandle*, const FfiBytes32*, FfiAccount* out_account) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_account_private");
    return fillAccount("wallet_ffi_get_account_private", out_account);
}

void wallet_ffi_free_account_data(FfiAccount* account) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_account_data");
    if (account && account->data) {
        free(account->data);
        account->data = nullptr;
        account->data_len = 0;
    }
}

WalletFfiError wallet_ffi_get_public_account_key(WalletHandle*, const FfiBytes32*, FfiPublicAccountKey* out_key) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_public_account_key");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_get_public_account_key");
    if (err == 0 && out_key) {
        memset(out_key->public_key.data, 0xBE, sizeof(out_key->public_key.data));
    }
    return static_cast<WalletFfiError>(err);
}

WalletFfiError wallet_ffi_get_private_account_keys(WalletHandle*, const FfiBytes32*, FfiPrivateAccountKeys* out_keys) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_private_account_keys");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_get_private_account_keys");
    if (err == 0 && out_keys) {
        memset(out_keys->nullifier_public_key.data, 0xEF, sizeof(out_keys->nullifier_public_key.data));
        out_keys->viewing_public_key = nullptr;
        out_keys->viewing_public_key_len = 0;
    }
    return static_cast<WalletFfiError>(err);
}

void wallet_ffi_free_private_account_keys(FfiPrivateAccountKeys* keys) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_private_account_keys");
    if (keys && keys->viewing_public_key) {
        free(keys->viewing_public_key);
        keys->viewing_public_key = nullptr;
        keys->viewing_public_key_len = 0;
    }
}

// === Account encoding ===

char* wallet_ffi_account_id_to_base58(const FfiBytes32*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_account_id_to_base58");
    const char* str = LOGOS_CMOCK_RETURN_STRING("wallet_ffi_account_id_to_base58");
    return strdup((str && *str) ? str : "MockBase58Address");
}

WalletFfiError wallet_ffi_account_id_from_base58(const char*, FfiBytes32* out_id) {
    LOGOS_CMOCK_RECORD("wallet_ffi_account_id_from_base58");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_account_id_from_base58");
    if (err == 0 && out_id) {
        memset(out_id->data, 0x5A, sizeof(out_id->data));
    }
    return static_cast<WalletFfiError>(err);
}

void wallet_ffi_free_string(char* s) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_string");
    if (s) {
        free(s);
    }
}

// === Blockchain synchronisation ===

int wallet_ffi_sync_to_block(WalletHandle*, uint64_t) {
    LOGOS_CMOCK_RECORD("wallet_ffi_sync_to_block");
    return LOGOS_CMOCK_RETURN(int, "wallet_ffi_sync_to_block");
}

WalletFfiError wallet_ffi_get_last_synced_block(WalletHandle*, uint64_t* out_block_id) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_last_synced_block");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_get_last_synced_block");
    if (err == 0 && out_block_id) {
        *out_block_id = static_cast<uint64_t>(LOGOS_CMOCK_RETURN(int, "last_synced_block_value"));
    }
    return static_cast<WalletFfiError>(err);
}

WalletFfiError wallet_ffi_get_current_block_height(WalletHandle*, uint64_t* out_block_height) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_current_block_height");
    const int err = LOGOS_CMOCK_RETURN(int, "wallet_ffi_get_current_block_height");
    if (err == 0 && out_block_height) {
        *out_block_height = static_cast<uint64_t>(LOGOS_CMOCK_RETURN(int, "current_block_height_value"));
    }
    return static_cast<WalletFfiError>(err);
}

// === Pinata claiming ===

WalletFfiError wallet_ffi_claim_pinata(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_claim_pinata");
    return fillTransferResult("wallet_ffi_claim_pinata", out_result);
}

WalletFfiError wallet_ffi_claim_pinata_private_owned_already_initialized(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16],
    uintptr_t, const uint8_t (*)[32], uintptr_t, FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_claim_pinata_private_owned_already_initialized");
    return fillTransferResult("wallet_ffi_claim_pinata_private_owned_already_initialized", out_result);
}

WalletFfiError wallet_ffi_claim_pinata_private_owned_not_initialized(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_claim_pinata_private_owned_not_initialized");
    return fillTransferResult("wallet_ffi_claim_pinata_private_owned_not_initialized", out_result);
}

// === Transfers / registration ===

WalletFfiError wallet_ffi_transfer_public(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_public");
    return fillTransferResult("wallet_ffi_transfer_public", out_result);
}

WalletFfiError wallet_ffi_transfer_shielded(
    WalletHandle*, const FfiBytes32*, const FfiPrivateAccountKeys*, const FfiU128*,
    const uint8_t (*)[16], 
    const char*,
    FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_shielded");
    return fillTransferResult("wallet_ffi_transfer_shielded", out_result);
}

WalletFfiError wallet_ffi_transfer_deshielded(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_deshielded");
    return fillTransferResult("wallet_ffi_transfer_deshielded", out_result);
}

WalletFfiError wallet_ffi_transfer_private(
    WalletHandle*, const FfiBytes32*, const FfiPrivateAccountKeys*, const FfiU128*,
    const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_private");
    return fillTransferResult("wallet_ffi_transfer_private", out_result);
}

WalletFfiError wallet_ffi_transfer_shielded_owned(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], 
    const char *,
    FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_shielded_owned");
    return fillTransferResult("wallet_ffi_transfer_shielded_owned", out_result);
}

WalletFfiError wallet_ffi_transfer_private_owned(
    WalletHandle*, const FfiBytes32*, const FfiBytes32*, const uint8_t (*)[16], FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_private_owned");
    return fillTransferResult("wallet_ffi_transfer_private_owned", out_result);
}

WalletFfiError wallet_ffi_register_public_account(WalletHandle*, const FfiBytes32*, FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_register_public_account");
    return fillTransferResult("wallet_ffi_register_public_account", out_result);
}

WalletFfiError wallet_ffi_register_private_account(WalletHandle*, const FfiBytes32*, FfiTransferResult* out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_register_private_account");
    return fillTransferResult("wallet_ffi_register_private_account", out_result);
}

void wallet_ffi_free_transfer_result(FfiTransferResult* result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_transfer_result");
    if (result && result->tx_hash) {
        free(result->tx_hash);
        result->tx_hash = nullptr;
    }
}

WalletFfiError wallet_ffi_transfer_elf(FfiProgram *ffi_program) {
    LOGOS_CMOCK_RECORD("wallet_ffi_transfer_elf");
    return fillProgram("wallet_ffi_transfer_elf", ffi_program);
}
WalletFfiError wallet_ffi_token_elf(FfiProgram *ffi_program) {
    LOGOS_CMOCK_RECORD("wallet_ffi_token_elf");
    return fillProgram("wallet_ffi_token_elf", ffi_program);
}
WalletFfiError wallet_ffi_ata_elf(FfiProgram *ffi_program) {
    LOGOS_CMOCK_RECORD("wallet_ffi_ata_elf");
    return fillProgram("wallet_ffi_ata_elf", ffi_program);
}
WalletFfiError wallet_ffi_amm_elf(FfiProgram *ffi_program) {
    LOGOS_CMOCK_RECORD("wallet_ffi_amm_elf");
    return fillProgram("wallet_ffi_amm_elf", ffi_program);
}

WalletFfiError wallet_ffi_resolve_public_account(FfiBytes32 account_id, bool needs_sign, FfiAccountIdentity *out_account_identity) {
    LOGOS_CMOCK_RECORD("wallet_ffi_resolve_public_account");
    return fillPublicAccountIdentity("wallet_ffi_resolve_public_account", out_account_identity);
}

WalletFfiError wallet_ffi_resolve_private_account(WalletHandle *handle, FfiBytes32 account_id, FfiAccountIdentity *out_account_identity){
    LOGOS_CMOCK_RECORD("wallet_ffi_resolve_private_account");
    return fillPrivateAccountIdentity("wallet_ffi_resolve_private_account", out_account_identity);
}

void wallet_ffi_free_instruction_words(FfiInstructionWords *words){
    LOGOS_CMOCK_RECORD("wallet_ffi_free_instruction_words");
    if (words && words->instruction_words) {
        free(words->instruction_words);
        words->instruction_words = nullptr;
        words->instruction_words_size = 0;
    }
}

void wallet_ffi_free_account_identity(FfiAccountIdentity *account_identity){
    LOGOS_CMOCK_RECORD("wallet_ffi_free_account_identity");
    if (account_identity && account_identity->viewing_public_key) {
        free(const_cast<uint8_t*>(account_identity->viewing_public_key));
        account_identity->viewing_public_key = nullptr;
        account_identity->viewing_public_key_len = 0;
    }
}

void wallet_ffi_free_transaction_result(FfiTransactionResult *result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_transaction_result");
    if (result && result->tx_hash) {
        free(const_cast<char*>(result->tx_hash));
        result->tx_hash = nullptr;
    }
} 

void wallet_ffi_free_ffi_program(FfiProgram *ffi_program) {
    LOGOS_CMOCK_RECORD("wallet_ffi_free_ffi_program");
    if (ffi_program && ffi_program->elf_data) {
        free(const_cast<uint8_t*>(ffi_program->elf_data));
        ffi_program->elf_data = nullptr;
        ffi_program->elf_size = 0;
    }
}

WalletFfiError wallet_ffi_send_generic_public_transaction(WalletHandle *handle, const FfiAccountIdentity *account_identities,
uintptr_t account_identities_size, const uint32_t *instruction_words, uintptr_t instruction_words_size,
const FfiProgramWithDependencies *program_with_dependencies, FfiTransactionResult *out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_send_generic_public_transaction");
    return fillTransactionResult("wallet_ffi_send_generic_public_transaction", out_result);
}

WalletFfiError wallet_ffi_send_generic_private_transaction(WalletHandle *handle, const FfiAccountIdentity *account_identities,
uintptr_t account_identities_size, const uint32_t *instruction_words, uintptr_t instruction_words_size,
const FfiProgramWithDependencies *program_with_dependencies, FfiTransactionResult *out_result){
    LOGOS_CMOCK_RECORD("wallet_ffi_send_generic_private_transaction");
    return fillTransactionResult("wallet_ffi_send_generic_private_transaction", out_result);
}    

WalletFfiError wallet_ffi_program_deployment(WalletHandle *handle, const uint8_t *elf_data, uintptr_t elf_size,
FfiTransactionResult *out_result) {
    LOGOS_CMOCK_RECORD("wallet_ffi_program_deployment");
    return fillTransactionResult("wallet_ffi_program_deployment", out_result);
}

// === Configuration ===

char* wallet_ffi_get_sequencer_addr(WalletHandle*) {
    LOGOS_CMOCK_RECORD("wallet_ffi_get_sequencer_addr");
    const char* addr = LOGOS_CMOCK_RETURN_STRING("wallet_ffi_get_sequencer_addr");
    return strdup((addr && *addr) ? addr : "127.0.0.1:3000");
}

} // extern "C"
