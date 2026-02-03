#ifndef I_LOGOS_EXECUTION_ZONE_WALLET_MODULE_API_H
#define I_LOGOS_EXECUTION_ZONE_WALLET_MODULE_API_H

#include <core/interface.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <wallet_ffi.h>
#ifdef __cplusplus
}
#endif

class ILogosExecutionZoneWalletModule {
public:
    virtual ~ILogosExecutionZoneWalletModule() = default;

    // Logos Core
    virtual void initLogos(LogosAPI* logosAPIInstance) = 0;
};

#define ILogosExecutionZoneWalletModule_iid "org.logos.ilogosexecutionzonewalletmodule"
Q_DECLARE_INTERFACE(ILogosExecutionZoneWalletModule, ILogosExecutionZoneWalletModule_iid)

#endif
