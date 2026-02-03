#include "logos_execution_zone_wallet_module.h"

#include <QtCore/QDebug>
#include <iostream>

LogosExecutionZoneWalletModule::LogosExecutionZoneWalletModule() = default;

LogosExecutionZoneWalletModule::~LogosExecutionZoneWalletModule() {

}

QString LogosExecutionZoneWalletModule::name() const {
    return "liblogos-execution-zone-wallet-module";
}

QString LogosExecutionZoneWalletModule::version() const {
    return "1.0.0";
}

void LogosExecutionZoneWalletModule::initLogos(LogosAPI* logosAPIInstance) {

}
