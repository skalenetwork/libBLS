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
            TEDataSingleton.h
            ../dkg/dkg_te.cpp
            ../dkg/DKGTEWrapper.cpp
            ../dkg/DKGTESecret.cpp
            utils.cpp
)

set(headers
            threshold_encryption.h
            TEDecryptSet.h
            TEPrivateKeyShare.h
            TEPrivateKey.h
            TEPublicKey.h
            TEPublicKeyShare.h
            TEDataSingleton.cpp
            ../dkg/dkg_te.h
            ../dkg/DKGTEWrapper.h
            ../dkg/DKGTESecret.h
            utils.h
)

set(PROJECT_VERSION 0.1.0)

set (THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
set (TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)

add_library(te ${sources} ${headers})

include_directories(${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})

target_include_directories(te PRIVATE ${GMP_INCLUDE_DIR})
target_link_libraries(te PRIVATE ${GMPXX_LIBRARY} ${GMP_LIBRARY})

include_directories(${CMAKE_BINARY_DIR}/deps/include )
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

target_include_directories(te PRIVATE ${PBC_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
target_link_libraries(te PRIVATE pbc)

if (BUILD_TESTS)
	add_executable(dkg_te_unit_test ../test/unit_tests_dkg_te.cpp)
	target_include_directories(dkg_te_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${TEST_DIR})
    target_link_libraries(dkg_te_unit_test PRIVATE te pbc ${GMP_LIBRARY} ${GMPXX_LIBRARY})

	add_test(NAME dkg_te_tests COMMAND dkg_te_unit_test)

	add_executable(te_unit_test ../test/unit_tests_te.cpp)
	target_include_directories(te_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_link_libraries(te_unit_test PRIVATE te pbc ${GMP_LIBRARY} ${GMPXX_LIBRARY})

	add_test(NAME te_tests COMMAND te_unit_test)

    add_executable(te_test ../test/test_TE_wrappers.cpp)
    target_include_directories(te_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${THIRD_PARTY_DIR})
    target_link_libraries(te_test PRIVATE te pbc ${GMP_LIBRARY} ${GMPXX_LIBRARY})

    add_test(NAME te_wrap_tests COMMAND te_unit_test)

    add_custom_target(all_te_tests
        COMMAND ./te_unit_test
        COMMAND ./te_test
        DEPENDS te_unit_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Run all TE tests"
        )
endif()
