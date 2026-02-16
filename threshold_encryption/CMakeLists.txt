cmake_minimum_required(VERSION 3.5)

project(libTE)

option(LIBBLS_BUILD_TESTS "Build tests" ON)

if(LIBBLS_BUILD_TESTS)
    enable_testing()
endif()

set(SOURCES
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
    CipheredKey.cpp
    Ciphertext.cpp
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
    CipheredKey.h
    Ciphertext.h
)

set(PROJECT_VERSION 0.2.0)

set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)

add_library(te ${SOURCES} ${HEADERS})

include_directories(${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})

include_directories(${CMAKE_BINARY_DIR}/deps/include )
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

# SYSTEM - silence warnings from third-party code
target_include_directories(te SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
target_link_libraries(te PRIVATE backend ${CRYPTOPP_LIBRARY})

target_compile_definitions(te
  INTERFACE
    $<TARGET_PROPERTY:backend,INTERFACE_COMPILE_DEFINITIONS>
)

if (LIBBLS_BUILD_TESTS)

    # Helper function to add tests
    function(add_te_test name source)
        add_executable(${name} ${source} ../test/utils.cpp)  # Includes utils only for tests
        target_include_directories(${name} SYSTEM PRIVATE
            ${THIRD_PARTY_DIR}
            boost_program_options
            ${CMAKE_CURRENT_SOURCE_DIR}
            ../test
        )

        if (EMSCRIPTEN)
            target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
            set_target_properties(${name} PROPERTIES LINK_FLAGS "-s -fwasm-exceptions")
        else()
            target_compile_options(${name} PRIVATE -Wno-format-overflow)
        endif()

        target_link_libraries(${name} PRIVATE te bls ${FOLLY_STATIC_LIBS})
    endfunction()

    add_te_test(te_unit_test ../test/unit_tests_te.cpp)
    add_te_test(te_test ../test/test_TE_wrappers.cpp)
    add_te_test(te_encrypt_message ../test/test_encrypt_message.cpp)
    add_test(NAME te_tests COMMAND te_unit_test)

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(te_sample_sgx ../test/te_sample_sgx.cpp ../test/utils.cpp)
        target_include_directories(te_sample_sgx SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR} ../test)
        target_link_libraries(te_sample_sgx PRIVATE te bls ${CRYPTOPP_LIBRARY} jsonrpccpp-client jsonrpccpp-server jsonrpccpp-common jsoncpp curl pthread ssl crypto z idn2)
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(decrypt_message ../tools/decryptMessage.cpp)
        target_include_directories(decrypt_message SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(decrypt_message PRIVATE te bls ${CRYPTOPP_LIBRARY})
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(generate_bls_keys ../tools/generateBLSKeys.cpp)
        target_include_directories(generate_bls_keys SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(generate_bls_keys PRIVATE te bls ${CRYPTOPP_LIBRARY})
    endif()

    if(NOT EMSCRIPTEN AND NOT APPLE)
        add_executable(encrypt_message ../test/encryptMessageJS.cpp)
        target_include_directories(encrypt_message SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
        target_link_libraries(encrypt_message PRIVATE te bls ${CRYPTOPP_LIBRARY})
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

if (NOT EMSCRIPTEN)
    # Build python threshold_encryption shared library
    add_library(t_encrypt_python SHARED ../threshold_encryption/encryptMessage.cpp)
    get_directory_property(PARENT_DIR PARENT_DIRECTORY)
    target_include_directories(t_encrypt_python PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PARENT_DIR})
    if(APPLE)
        target_link_libraries(t_encrypt_python PRIVATE
            -Wl,-force_load,$<TARGET_FILE:te>
            -Wl,-force_load,$<TARGET_FILE:bls>
            -Wl,-force_load,$<TARGET_FILE:common_utils>
            backend ${FOLLY_STATIC_LIBS} ${CRYPTOPP_LIBRARY})
        # Explicitly add dependencies for Apple builds because they are hidden inside linker flags
        add_dependencies(t_encrypt_python te bls common_utils)
    else()
        target_link_libraries(t_encrypt_python PRIVATE
            -Wl,--whole-archive te bls common_utils -Wl,--no-whole-archive
            backend ${FOLLY_STATIC_LIBS} ${CRYPTOPP_LIBRARY})
    endif()
endif()

if (EMSCRIPTEN)
    add_executable(encrypt ../threshold_encryption/encryptMessage.cpp ../tools/utils.cpp)
    set_target_properties(encrypt PROPERTIES LINK_FLAGS "-s EXIT_RUNTIME=1 -s USE_PTHREADS=0 -s MODULARIZE -s ALLOW_MEMORY_GROWTH=1 -s NO_DISABLE_EXCEPTION_CATCHING=1 -s EXPORTED_RUNTIME_METHODS='[\"ccall\"]' -s EXPORTED_FUNCTIONS='[\"_encryptMessage\", \"_encryptMessageDualKey\",\"_encryptMessageMockup\"]' -s ENVIRONMENT='node,web' -s SINGLE_FILE=1")
    target_include_directories(encrypt SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_compile_definitions(encrypt PRIVATE MCL=1)
    target_link_libraries(encrypt PRIVATE te)

    add_executable(encrypt_message ../test/encryptMessageJS.cpp ../tools/utils.cpp)
    target_include_directories(encrypt_message SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_compile_definitions(encrypt_message PRIVATE MCL=1)
    set_target_properties(encrypt_message PROPERTIES LINK_FLAGS "-s EXIT_RUNTIME=1 -s USE_PTHREADS=0 -s EXPORTED_FUNCTIONS=['_main'] --bind")
    target_link_libraries(encrypt_message PRIVATE te ${CRYPTOPP_LIBRARY})
endif()
