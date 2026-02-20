cmake_minimum_required(VERSION 3.20)
project(logos_execution_zone_wallet_module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Options ----
option(LOGOS_MODULE_BUNDLE "Create local runtime bundle in target/." ON)
set(LOGOS_CORE_ROOT "" CACHE PATH "Path to logos-core root directory.")
set(LOGOS_EXECUTION_ZONE_WALLET_ROOT "" CACHE PATH "Path to logos-execution-zone-wallet source root.")
set(LOGOS_EXECUTION_ZONE_WALLET_LIB "" CACHE PATH "Path to prebuilt logos-execution-zone-wallet lib.")
set(LOGOS_EXECUTION_ZONE_WALLET_INCLUDE "" CACHE PATH "Path to prebuilt logos-execution-zone-wallet include.")

set(HAS_LOGOS_CORE_ROOT FALSE)
set(HAS_LOGOS_EXECUTION_ZONE_WALLET_ROOT FALSE)
set(HAS_LOGOS_EXECUTION_ZONE_WALLET_LIB FALSE)
set(HAS_LOGOS_EXECUTION_ZONE_WALLET_INCLUDE FALSE)

if (DEFINED LOGOS_CORE_ROOT AND NOT "${LOGOS_CORE_ROOT}" STREQUAL "")
    set(HAS_LOGOS_CORE_ROOT TRUE)
endif()

if (DEFINED LOGOS_EXECUTION_ZONE_WALLET_ROOT AND NOT "${LOGOS_EXECUTION_ZONE_WALLET_ROOT}" STREQUAL "")
    set(HAS_LOGOS_EXECUTION_ZONE_WALLET_ROOT TRUE)
endif()

if(DEFINED LOGOS_EXECUTION_ZONE_WALLET_LIB AND NOT "${LOGOS_EXECUTION_ZONE_WALLET_LIB}" STREQUAL "")
    set(HAS_LOGOS_EXECUTION_ZONE_WALLET_LIB TRUE)
endif()

if(DEFINED LOGOS_EXECUTION_ZONE_WALLET_INCLUDE AND NOT "${LOGOS_EXECUTION_ZONE_WALLET_INCLUDE}" STREQUAL "")
    set(HAS_LOGOS_EXECUTION_ZONE_WALLET_INCLUDE TRUE)
endif()

if (NOT HAS_LOGOS_CORE_ROOT)
    message(FATAL_ERROR "LOGOS_CORE_ROOT must be set to the logos-core root directory.")
endif()

if(HAS_LOGOS_EXECUTION_ZONE_WALLET_LIB AND HAS_LOGOS_EXECUTION_ZONE_WALLET_INCLUDE AND NOT HAS_LOGOS_EXECUTION_ZONE_WALLET_ROOT)
    message(STATUS "Using prebuilt logos-execution-zone-wallet.")
    set(LOGOS_EXECUTION_ZONE_PREBUILT TRUE)
elseif(NOT HAS_LOGOS_EXECUTION_ZONE_WALLET_LIB AND NOT HAS_LOGOS_EXECUTION_ZONE_WALLET_INCLUDE AND HAS_LOGOS_EXECUTION_ZONE_WALLET_ROOT)
    message(STATUS "Building logos-execution-zone-wallet from source.")
    set(LOGOS_EXECUTION_ZONE_PREBUILT FALSE)
else()
    message(FATAL_ERROR "Either both LOGOS_EXECUTION_ZONE_WALLET_LIB and LOGOS_EXECUTION_ZONE_WALLET_INCLUDE must be set for prebuilt logos-execution-zone-wallet, or LOGOS_EXECUTION_ZONE_WALLET_ROOT must be set to build from source.")
endif()

# ---- Qt ----
find_package(Qt6 REQUIRED COMPONENTS Core RemoteObjects)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# ---- Directories ----
set(WORKSPACE_ROOT  "${CMAKE_BINARY_DIR}/workspace")
file(MAKE_DIRECTORY "${WORKSPACE_ROOT}")

# ---- Logos Core SDK ----
set(SDK_LIB "${LOGOS_CORE_ROOT}/lib/liblogos_sdk.a")
set(SDK_INC "${LOGOS_CORE_ROOT}/include")

# ---- OS Specifics ----
if(APPLE)
    set(DYLIB_EXT ".dylib")
elseif(WIN32)
    set(DYLIB_EXT ".dll")
    set(IMPLIB_EXT ".lib")
else()
    set(DYLIB_EXT ".so")
endif()

# NOTE (Windows):
# Rust cdylib typically produces:
#   - logos_blockchain.dll (runtime)
#   - logos_blockchain.lib (import lib)
# The Windows build hasn't been yet, so adjust accordingly if the DLL is named without the 'lib' prefix.

# ---- Logos Blockchain (build OR consume) ----
if(LOGOS_EXECUTION_ZONE_PREBUILT)
    set(LOGOS_EXECUTION_ZONE_DYLIB "${LOGOS_EXECUTION_ZONE_WALLET_LIB}/libwallet_ffi${DYLIB_EXT}")

    if(WIN32)
        set(LOGOS_EXECUTION_ZONE_IMPLIB "${LOGOS_EXECUTION_ZONE_WALLET_LIB}/wallet_ffi${IMPLIB_EXT}")
    endif()

    add_custom_target(logos_execution_zone_libs)

else()
    find_program(CARGO_EXECUTABLE cargo REQUIRED)

    set(CARGO_TARGET_DIR       "${WORKSPACE_ROOT}/logos-execution-zone/target")
    set(INTERNAL_STAGE         "${WORKSPACE_ROOT}/stage")
    set(INTERNAL_STAGE_LIB     "${INTERNAL_STAGE}/lib")
    set(INTERNAL_STAGE_INCLUDE "${INTERNAL_STAGE}/include")
    file(MAKE_DIRECTORY "${CARGO_TARGET_DIR}" "${INTERNAL_STAGE_LIB}" "${INTERNAL_STAGE_INCLUDE}")

    set(LOGOS_EXECUTION_ZONE_WALLET_LIB     "${INTERNAL_STAGE_LIB}")
    set(LOGOS_EXECUTION_ZONE_WALLET_INCLUDE "${INTERNAL_STAGE_INCLUDE}")

    set(LOGOS_EXECUTION_ZONE_DYLIB  "${INTERNAL_STAGE_LIB}/libwallet_ffi${DYLIB_EXT}")
    set(LOGOS_EXECUTION_ZONE_HEADER "${INTERNAL_STAGE_INCLUDE}/wallet_ffi.h")

    add_custom_command(
            OUTPUT "${LOGOS_EXECUTION_ZONE_DYLIB}"
            COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${CARGO_TARGET_DIR}
            ${CARGO_EXECUTABLE} build --release
            --package wallet-ffi
            --manifest-path "${LOGOS_EXECUTION_ZONE_WALLET_ROOT}/Cargo.toml"
            COMMAND ${CMAKE_COMMAND} -E copy
            "${CARGO_TARGET_DIR}/release/libwallet_ffi${DYLIB_EXT}"
            "${LOGOS_EXECUTION_ZONE_DYLIB}"
            DEPENDS "${LOGOS_EXECUTION_ZONE_WALLET_ROOT}/Cargo.toml"
            VERBATIM
    )

    add_custom_command(
            OUTPUT "${LOGOS_EXECUTION_ZONE_HEADER}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LOGOS_EXECUTION_ZONE_WALLET_ROOT}/wallet-ffi/wallet_ffi.h"
            "${LOGOS_EXECUTION_ZONE_HEADER}"
            DEPENDS "${LOGOS_EXECUTION_ZONE_DYLIB}"
            VERBATIM
    )

    add_custom_target(logos_execution_zone_libs DEPENDS "${LOGOS_EXECUTION_ZONE_DYLIB}" "${LOGOS_EXECUTION_ZONE_HEADER}")
endif()

# ---- Imported targets ----
add_library(logos_execution_zone_wallet SHARED IMPORTED GLOBAL)
set_target_properties(logos_execution_zone_wallet PROPERTIES
        IMPORTED_LOCATION "${LOGOS_EXECUTION_ZONE_DYLIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${LOGOS_EXECUTION_ZONE_WALLET_INCLUDE}"
)

if(NOT LOGOS_EXECUTION_ZONE_PREBUILT)
    add_dependencies(logos_execution_zone_wallet logos_execution_zone_libs)
endif()

if(WIN32)
    set_target_properties(logos_execution_zone_wallet PROPERTIES IMPORTED_IMPLIB "${LOGOS_EXECUTION_ZONE_IMPLIB}")
endif()

add_library(logos_core STATIC IMPORTED
        src/i_logos_execution_zone_wallet_module.h)
set_target_properties(logos_core PROPERTIES
        IMPORTED_LOCATION "${SDK_LIB}"
)

add_library(logos_cpp_sdk INTERFACE)
target_include_directories(logos_cpp_sdk INTERFACE "${SDK_INC}")

# ---- Plugin ----
set(PLUGIN_TARGET logos_execution_zone_wallet_module)

qt_add_plugin(${PLUGIN_TARGET} CLASS_NAME LogosExecutionZoneWalletModule)

target_sources(${PLUGIN_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logos_execution_zone_wallet_module.cpp
)

set_property(TARGET ${PLUGIN_TARGET} PROPERTY PUBLIC_HEADER
        ${CMAKE_CURRENT_SOURCE_DIR}/src/i_logos_execution_zone_wallet_module.h
)

target_include_directories(${PLUGIN_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PLUGIN_TARGET} PRIVATE
        Qt6::Core
        Qt6::RemoteObjects
        logos_execution_zone_wallet
        logos_cpp_sdk
        logos_core
)

target_compile_definitions(${PLUGIN_TARGET} PRIVATE
        LOGOS_EXECUTION_ZONE_WALLET_MODULE_METADATA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/metadata.json"
)

add_dependencies(${PLUGIN_TARGET} logos_execution_zone_libs)

if(APPLE)
    set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH "@loader_path"
            INSTALL_RPATH "@loader_path"
    )
elseif(UNIX)
    set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
    )
endif()

# ---- Install ----
install(TARGETS ${PLUGIN_TARGET}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        PUBLIC_HEADER DESTINATION include
)
install(DIRECTORY "${LOGOS_EXECUTION_ZONE_WALLET_INCLUDE}/" DESTINATION include)
install(FILES "${LOGOS_EXECUTION_ZONE_DYLIB}" DESTINATION lib)
