#ifndef MOCK_CORE_FFI_CAPTURE_H
#define MOCK_CORE_FFI_CAPTURE_H

// LogosCMockStore (logos_clib_mock.h) only lets tests control return values, not
// inspect call arguments. The transfer_shielded/transfer_private identifier logic
// needs the latter, so capture the relevant args here in plain static storage.

#include <cstdint>
#include <vector>

extern "C" {
#include <core_ffi.h>
}

namespace MockWalletFfiCapture {

extern uint8_t lastTransferShieldedIdentifier[32];
extern uint8_t lastTransferPrivateIdentifier[32];

// Last generic transaction's arguments. Pointers inside are only valid during the call.
extern std::vector<FfiAccountMention> lastMentions;
// Each last mention's viewing public key bytes, copied while the call's pointers were valid.
extern std::vector<std::vector<uint8_t>> lastViewingPublicKeys;
extern FfiBytes32 lastSelfAccountId;
extern std::vector<FfiDependency> lastPrograms;

} // namespace MockWalletFfiCapture

#endif // MOCK_CORE_FFI_CAPTURE_H
