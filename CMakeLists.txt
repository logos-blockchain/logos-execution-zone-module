cmake_minimum_required(VERSION 3.14)
project(LogosExecutionZoneWalletModule LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include the Logos Module CMake helper
if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

logos_module(
    NAME lez_wallet_module
    SOURCES
        src/logos_execution_zone_wallet_module.h
        src/logos_execution_zone_wallet_module.cpp
        src/i_logos_execution_zone_wallet_module.h
    EXTERNAL_LIBS
        wallet_ffi
)
