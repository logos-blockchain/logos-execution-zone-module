cmake_minimum_required(VERSION 3.14)
project(LEZCoreTests LANGUAGES CXX)

include(LogosTest)

# Unit tests (mocked core_ffi)

logos_test(
    NAME lez_core_module_tests
    MODULE_SOURCES
        ../src/lez_core_module.cpp
    TEST_SOURCES
        main.cpp
        test_lez_core.cpp
    MOCK_C_SOURCES
        mocks/mock_core_ffi.cpp
    EXTRA_INCLUDES
        stubs
)

# The module targets C++20 (uses __uint128_t); LogosTest.cmake defaults to C++17.
set_target_properties(lez_core_module_tests PROPERTIES CXX_STANDARD 20)

# Integration tests (real core_ffi library)

find_library(CORE_FFI_PATH
    NAMES core_ffi libcore_ffi core libcore
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../lib
    NO_DEFAULT_PATH)

if(CORE_FFI_PATH)
    message(STATUS "[LEZCoreTests] core_ffi found: ${CORE_FFI_PATH} - building integration tests")

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
            ${CORE_FFI_PATH}
    )

    set_target_properties(lez_core_module_integration_tests PROPERTIES CXX_STANDARD 20)

    get_filename_component(CORE_FFI_DIR "${CORE_FFI_PATH}" DIRECTORY)
    set_target_properties(lez_core_module_integration_tests PROPERTIES
        BUILD_RPATH "${CORE_FFI_DIR}"
    )
else()
    message(STATUS "[LEZCoreTests] core_ffi not found in ../lib - skipping integration tests")
endif()
