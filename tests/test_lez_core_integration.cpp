// Integration tests for LEZCoreModule — uses the REAL wallet_ffi
// library. No mocking. Limited to network-free, wallet-handle-free pure functions
// so the suite stays deterministic and offline.
//
// Requires the real wallet library (and wallet_ffi.h header) in ../lib at build
// time. Skipped automatically when the library is not found (see CMakeLists.txt).

#include "lez_core_module.h"
#include <logos_test.h>

#include <atomic>
#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace {

    class IntegrationProfileRoot {
    public:
        IntegrationProfileRoot() {
            static std::atomic<uint64_t> sequence{0};
            path = std::filesystem::temp_directory_path() /
                   ("lez-core-integration-" + std::to_string(sequence.fetch_add(1)));
            std::filesystem::remove_all(path);
            std::filesystem::create_directories(path);
        }

        ~IntegrationProfileRoot() {
            std::error_code error;
            std::filesystem::remove_all(path, error);
        }

        std::filesystem::path path;
    };

    nlohmann::json parseIntegrationResult(const std::string& value) {
        return nlohmann::json::parse(value, nullptr, false);
    }

} // namespace

// account_id_to_base58 and account_id_from_base58 are pure encoding helpers that
// do not require an open wallet, so they can be exercised against the real lib.
LOGOS_TEST(integration_account_id_base58_round_trip) {
    LEZCoreModule module;

    const std::string idHex = std::string(64, 'a');

    const std::string base58 = module.account_id_to_base58(idHex);
    LOGOS_ASSERT_FALSE(base58.empty());

    const std::string decodedHex = module.account_id_from_base58(base58);
    LOGOS_ASSERT_FALSE(decodedHex.empty());
    LOGOS_ASSERT_EQ(decodedHex, idHex);
}

LOGOS_TEST(integration_account_id_from_base58_rejects_garbage) {
    LEZCoreModule module;

    // Clearly invalid base58 input should not decode to a valid id.
    LOGOS_ASSERT_TRUE(module.account_id_from_base58("!!!not-base58!!!").empty());
}

// This target is only built when a real wallet_ffi library is deliberately
// supplied in ../lib. Unlike the encoding tests above, this lifecycle test can
// contact the official LEZ testnet while the wallet library initializes and
// saves statistics.
LOGOS_TEST(integration_default_profile_create_save_destroy_and_reopen) {
    IntegrationProfileRoot root;
    std::string mnemonic;
    LogosList accountsBeforeRestart;

    {
        LEZCoreModule module;
        module._logosCoreSetContext_("/module", "integration", root.path.string());
        const nlohmann::json created = parseIntegrationResult(module.create_default("integration-test-password"));
        LOGOS_ASSERT_TRUE(created["success"].get<bool>());
        mnemonic = created["mnemonic"].get<std::string>();
        LOGOS_ASSERT_FALSE(mnemonic.empty());

        LOGOS_ASSERT_FALSE(module.create_account_public().empty());
        accountsBeforeRestart = module.list_accounts();
        LOGOS_ASSERT_FALSE(accountsBeforeRestart.empty());
        LOGOS_ASSERT_EQ(module.save(), static_cast<int64_t>(SUCCESS));
    }

    {
        LEZCoreModule module;
        module._logosCoreSetContext_("/module", "integration", root.path.string());
        const nlohmann::json status = parseIntegrationResult(module.wallet_status());
        LOGOS_ASSERT_EQ(status["state"].get<std::string>(), std::string("closed"));
        const nlohmann::json opened = parseIntegrationResult(module.open_default());
        LOGOS_ASSERT_TRUE(opened["success"].get<bool>());
        LOGOS_ASSERT_EQ(module.list_accounts(), accountsBeforeRestart);
    }

    IntegrationProfileRoot restoredRoot;
    LEZCoreModule restored;
    restored._logosCoreSetContext_("/module", "integration-restored", restoredRoot.path.string());
    const nlohmann::json restoreResult =
        parseIntegrationResult(restored.restore_default(mnemonic, "integration-test-password", 5));
    LOGOS_ASSERT_TRUE(restoreResult["success"].get<bool>());
    LOGOS_ASSERT_FALSE(restoreResult.contains("mnemonic"));
    LOGOS_ASSERT_EQ(restored.list_accounts(), accountsBeforeRestart);
}
