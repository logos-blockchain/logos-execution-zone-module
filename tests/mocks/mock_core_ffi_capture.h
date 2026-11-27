#ifndef MOCK_CORE_FFI_CAPTURE_H
#define MOCK_CORE_FFI_CAPTURE_H

// LogosCMockStore (logos_clib_mock.h) only lets tests control return values, not
// inspect call arguments. The transfer_shielded/transfer_private identifier logic
// needs the latter, so capture the relevant args here in plain static storage.

#include <atomic>
#include <cstdint>
#include <string>
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

// Last sequencer setup/start's home and JSON args, copied while the call's pointers were valid;
// empty for a null one.
extern std::string lastSequencerHome;
extern std::string lastSequencerJson;

// The wallet's sticky fee settings: as they are now, and as they were when the last send ran.
struct FeeSettings {
    bool dry_run = false;
    bool allow_revert = false;
    bool has_fee_params = false;
    FfiFeeParams fee_params{};
};
// While set, sequencer_ffi_start_sequencer does not return.
extern std::atomic<bool> holdSequencerStart;
extern std::atomic<int> sequencerStartsFinished;
extern std::atomic<int> sequencerStops;

extern FeeSettings feeSettings;
extern FeeSettings feeSettingsAtLastSend;

} // namespace MockWalletFfiCapture

#endif // MOCK_CORE_FFI_CAPTURE_H
