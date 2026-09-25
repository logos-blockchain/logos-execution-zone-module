#ifndef MOCK_WALLET_FFI_CAPTURE_H
#define MOCK_WALLET_FFI_CAPTURE_H

// LogosCMockStore (logos_clib_mock.h) only lets tests control return values, not
// inspect call arguments. The transfer_shielded/transfer_private identifier logic
// needs the latter, so capture the relevant args here in plain static storage.

#include <cstdint>
#include <vector>

extern "C" {
#include <wallet_ffi.h>
}

namespace MockWalletFfiCapture {

extern uint8_t lastTransferShieldedIdentifier[16];
extern uint8_t lastTransferPrivateIdentifier[16];

// Last generic transaction's arguments. Pointers inside are only valid during the call.
extern std::vector<FfiAccountMention> lastMentions;
extern FfiBytes32 lastSelfAccountId;
extern std::vector<FfiDependency> lastPrograms;

} // namespace MockWalletFfiCapture

#endif // MOCK_WALLET_FFI_CAPTURE_H
