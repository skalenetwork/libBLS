cmake_minimum_required(VERSION 3.5.1)

project(libTE)

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
endif()

set(SOURCES
    ${TOOLS_DIR}/utils.cpp
    threshold_encryption.cpp
    TEBase.cpp
    TEDecryptionShare.cpp
    TEDecryptSet.cpp
    TEPrivateKeyShare.cpp
    TEPrivateKey.cpp
    TEPublicKey.cpp
    TEPublicKeyShare.cpp
    ThresholdEncryption.cpp
    AesGcmCipher.cpp
)

set(HEADERS
    ${TOOLS_DIR}/utils.h
    threshold_encryption.h
    TEBase.h
    TEDecryptionShare.h
    TEDecryptSet.h
    TEPrivateKeyShare.h
    TEPrivateKey.h
    TEPublicKey.h
    TEPublicKeyShare.h
    ThresholdEncryption.h
    AesGcmCipher.h
)

set(PROJECT_VERSION 0.2.0)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)

add_library(te ${SOURCES} ${HEADERS})

include_directories(${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})

include_directories(${CMAKE_BINARY_DIR}/deps/include )
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

target_include_directories(te PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
target_link_libraries(te PRIVATE bls ${CRYPTOPP_LIBRARY} backend)

if (BUILD_TESTS)

    # Helper function to add tests
    function(add_te_test name source)
        add_executable(${name} ${source} ../test/utils.cpp)  # Includes utils only for tests
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR} ../test)

        if (EMSCRIPTEN)
            target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
            set_target_properties(${name} PROPERTIES LINK_FLAGS "-s -fwasm-exceptions")
        else()
            target_compile_options(${name} PRIVATE -Wno-format-overflow)
        endif()

        target_link_libraries(${name} PRIVATE te backend bls)
    endfunction()

    add_te_test(te_unit_test ../test/unit_tests_te.cpp)
    add_te_test(te_test ../test/test_TE_wrappers.cpp)
    add_te_test(te_encrypt_message ../test/test_encrypt_message.cpp)
    add_test(NAME te_tests COMMAND te_unit_test)

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(te_sample_sgx ../test/te_sample_sgx.cpp ../test/utils.cpp) 
        target_include_directories(te_sample_sgx PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR} ../test)
        target_link_libraries(te_sample_sgx PRIVATE te bls ${CRYPTOPP_LIBRARY} backend jsonrpccpp-client jsonrpccpp-server jsonrpccpp-common jsoncpp curl pthread ssl crypto z idn2)
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(decrypt_message ../tools/decryptMessage.cpp) 
        target_include_directories(decrypt_message PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(decrypt_message PRIVATE te ${CRYPTOPP_LIBRARY} backend)
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(generate_bls_keys ../tools/generateBLSKeys.cpp)
        target_include_directories(generate_bls_keys PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(generate_bls_keys PRIVATE te ${CRYPTOPP_LIBRARY} backend)
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(encrypt_message ../test/encryptMessageJS.cpp)
        target_include_directories(encrypt_message PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(encrypt_message PRIVATE te ${CRYPTOPP_LIBRARY} backend)
    endif()

    add_test(NAME te_wrap_tests COMMAND te_unit_test)

    add_custom_target(all_te_tests
        COMMAND ./te_unit_test
        COMMAND ./te_test
        DEPENDS te_unit_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Run all TE tests"
    )
endif()

if (EMSCRIPTEN)
    add_executable(encrypt ../threshold_encryption/encryptMessage.cpp)
    set_target_properties(encrypt PROPERTIES LINK_FLAGS "-s EXIT_RUNTIME=1 -s USE_PTHREADS=0 -s MODULARIZE -s ALLOW_MEMORY_GROWTH=1 -s NO_DISABLE_EXCEPTION_CATCHING=1 -s EXPORTED_RUNTIME_METHODS='[\"ccall\"]' -s EXPORTED_FUNCTIONS='[\"_encryptMessage\", \"_encryptMessageMockup\"]' -s MAIN_MODULE=1 -s ENVIRONMENT='node,web' -s SINGLE_FILE=1")
    target_include_directories(encrypt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_link_libraries(encrypt PRIVATE te ${CRYPTOPP_LIBRARY} backend)

    add_executable(encrypt_message ../test/encryptMessageJS.cpp)
    target_include_directories(encrypt_message PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_compile_options(encrypt_message PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
    set_target_properties(encrypt_message PROPERTIES LINK_FLAGS "-s EXIT_RUNTIME=1 -s USE_PTHREADS=0 -s EXPORTED_FUNCTIONS=['_main'] -s MAIN_MODULE=1 --bind")
    target_link_libraries(encrypt_message PRIVATE te ${CRYPTOPP_LIBRARY} backend)
endif()
