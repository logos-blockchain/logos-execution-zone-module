// Integration tests for LogosExecutionZoneWalletModule — uses the REAL wallet_ffi
// library. No mocking. Limited to network-free, wallet-handle-free pure functions
// so the suite stays deterministic and offline.
//
// Requires the real wallet library (and wallet_ffi.h header) in ../lib at build
// time. Skipped automatically when the library is not found (see CMakeLists.txt).

#include <logos_test.h>
#include "logos_execution_zone_wallet_module.h"

#include <QString>

// account_id_to_base58 and account_id_from_base58 are pure encoding helpers that
// do not require an open wallet, so they can be exercised against the real lib.
LOGOS_TEST(integration_account_id_base58_round_trip) {
    LogosExecutionZoneWalletModule module;

    const QString idHex = QString(64, 'a');

    const QString base58 = module.account_id_to_base58(idHex);
    LOGOS_ASSERT_FALSE(base58.isEmpty());

    const QString decodedHex = module.account_id_from_base58(base58);
    LOGOS_ASSERT_FALSE(decodedHex.isEmpty());
    LOGOS_ASSERT_EQ(decodedHex, idHex);
}

LOGOS_TEST(integration_account_id_from_base58_rejects_garbage) {
    LogosExecutionZoneWalletModule module;

    // Clearly invalid base58 input should not decode to a valid id.
    LOGOS_ASSERT_TRUE(module.account_id_from_base58(QStringLiteral("!!!not-base58!!!")).isEmpty());
}
