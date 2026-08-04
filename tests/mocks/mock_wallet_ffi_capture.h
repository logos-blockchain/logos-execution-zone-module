#ifndef MOCK_WALLET_FFI_CAPTURE_H
#define MOCK_WALLET_FFI_CAPTURE_H

// LogosCMockStore (logos_clib_mock.h) only lets tests control return values, not
// inspect call arguments. The transfer_shielded/transfer_private identifier logic
// needs the latter, so capture the relevant args here in plain static storage.

#include <cstdint>
#include <string>

namespace MockWalletFfiCapture {

extern uint8_t lastTransferShieldedIdentifier[16];
extern uint8_t lastTransferPrivateIdentifier[16];
    extern std::string lastCreateConfigPath;
    extern std::string lastCreateStoragePath;
    extern std::string lastCreateStatisticsPath;
    extern std::string lastOpenConfigPath;
    extern std::string lastOpenStoragePath;
    extern std::string lastOpenStatisticsPath;

} // namespace MockWalletFfiCapture

#endif // MOCK_WALLET_FFI_CAPTURE_H
