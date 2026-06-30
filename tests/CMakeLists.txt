cmake_minimum_required(VERSION 3.14)
project(LEZCoreTests LANGUAGES CXX)

include(LogosTest)

# Unit tests (mocked wallet_ffi)

logos_test(
    NAME lez_core_module_tests
    MODULE_SOURCES
        ../src/lez_core_module.cpp
    TEST_SOURCES
        main.cpp
        test_lez_core.cpp
    MOCK_C_SOURCES
        mocks/mock_wallet_ffi.cpp
    EXTRA_INCLUDES
        stubs
)

# The module targets C++20 (uses __uint128_t); LogosTest.cmake defaults to C++17.
set_target_properties(lez_core_module_tests PROPERTIES CXX_STANDARD 20)

# Integration tests (real wallet_ffi library)

find_library(WALLET_FFI_PATH
    NAMES wallet_ffi libwallet_ffi wallet libwallet
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../lib
    NO_DEFAULT_PATH)

if(WALLET_FFI_PATH)
    message(STATUS "[LEZCoreTests] wallet_ffi found: ${WALLET_FFI_PATH} - building integration tests")

    logos_test(
        NAME lez_core_module_integration_tests
        MODULE_SOURCES
            ../src/lez_core_module.cpp
        TEST_SOURCES
            main.cpp
            test_lez_core_integration.cpp
        EXTRA_INCLUDES
            ../lib
        EXTRA_LINK_LIBS
            ${WALLET_FFI_PATH}
    )

    set_target_properties(lez_core_module_integration_tests PROPERTIES CXX_STANDARD 20)

    get_filename_component(WALLET_FFI_DIR "${WALLET_FFI_PATH}" DIRECTORY)
    set_target_properties(lez_core_module_integration_tests PROPERTIES
        BUILD_RPATH "${WALLET_FFI_DIR}"
    )
else()
    message(STATUS "[LEZCoreTests] wallet_ffi not found in ../lib - skipping integration tests")
endif()
