cmake_minimum_required(VERSION 3.5.1)

project(libTE)

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
	enable_testing()
endif()

set(sources
            threshold_encryption.cpp
            TEDecryptSet.cpp
            TEPrivateKeyShare.cpp
            TEPrivateKey.cpp
            TEPublicKey.cpp
            TEPublicKeyShare.cpp
            ${DKG_DIR}/dkg_te.cpp
            ${DKG_DIR}/DKGTEWrapper.cpp
            ${DKG_DIR}/DKGTESecret.cpp
            ${TOOLS_DIR}/utils.cpp
)

set(headers
            threshold_encryption.h
            TEDecryptSet.h
            TEPrivateKeyShare.h
            TEPrivateKey.h
            TEPublicKey.h
            TEPublicKeyShare.h
            ${DKG_DIR}/dkg_te.h
            ${DKG_DIR}/DKGTEWrapper.h
            ${DKG_DIR}/DKGTESecret.h
            ${TOOLS_DIR}/utils.h
)

set(PROJECT_VERSION 0.2.0)

set (THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
set (TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)

add_library(te ${sources} ${headers})

include_directories(${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})

include_directories(${CMAKE_BINARY_DIR}/deps/include )
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

target_include_directories(te PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
target_link_libraries(te PRIVATE ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

if (BUILD_TESTS)
	add_executable(te_unit_test ../test/unit_tests_te.cpp)
	target_include_directories(te_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_link_libraries(te_unit_test PRIVATE te ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

	add_test(NAME te_tests COMMAND te_unit_test)

    add_executable(te_test ../test/test_TE_wrappers.cpp)
    target_include_directories(te_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_link_libraries(te_test PRIVATE te ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

    add_test(NAME te_wrap_tests COMMAND te_unit_test)

    add_custom_target(all_te_tests
        COMMAND ./te_unit_test
        COMMAND ./te_test
        DEPENDS te_unit_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Run all TE tests"
    )
endif()
