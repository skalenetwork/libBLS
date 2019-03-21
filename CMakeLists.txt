cmake_minimum_required(VERSION 3.5.1)

project(libBLS)	

option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
	enable_testing()
endif()

set(sourses_bls
    bls/bls.cpp
    dkg/dkg.cpp
    third_party/cryptlite/base64.cpp
    third_party/json.hpp
)

set(headers_bls
    bls/bls.h
    dkg/dkg.h
    third_party/cryptlite/sha256.h
    third_party/cryptlite/sha1.h		
    third_party/cryptlite/hmac.h
    third_party/cryptlite/base64.h
)

add_definitions( -DBLS_VERSION=0.1.0 )

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -fPIC -std=c++11 -Wno-error=parentheses -Wno-error=char-subscripts -Wno-unused-variable")

include_directories(${CMAKE_BINARY_DIR}/deps/include /usr/include/python3.5m)

link_directories(${CMAKE_BINARY_DIR}/deps/lib usr/lib/python3.5)

include_directories(${CMAKE_BINARY_DIR}/deps/include ${GMP_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/libff )

link_directories(${CMAKE_BINARY_DIR}/deps/lib)

include(deps/ProjectGMP.cmake)
include(deps/ProjectSecp256k1.cmake)

add_subdirectory(libff)

add_library(bls ${sourses_bls} ${headers_bls})
add_dependencies(bls gmp ff secp256k1)
target_include_directories(bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls PRIVATE ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

add_executable(dkg_keygen tools/dkg_key_gen.cpp)
target_include_directories(dkg_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dkg_keygen PRIVATE bls boost_program_options)

add_executable(sign_bls tools/sign_bls.cpp)
target_include_directories(sign_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sign_bls PRIVATE bls boost_program_options)

add_executable(verify_bls tools/verify_bls.cpp)
target_include_directories(verify_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(verify_bls PRIVATE bls boost_program_options)

if (BUILD_TESTS)
	add_executable(bls_unit_test test/unit_tests_bls.cpp)
	target_include_directories(bls_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(bls_unit_test PRIVATE bls ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

	add_test(NAME bls_tests COMMAND bls_unit_test)

	add_executable(dkg_unit_test test/unit_tests_dkg.cpp)
	target_include_directories(dkg_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(dkg_unit_test PRIVATE bls ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

	add_test(NAME dkg_tests COMMAND dkg_unit_test)

	add_custom_target( all_bls_tests
		COMMAND ./bls_unit_test
		COMMAND ./dkg_unit_test
		DEPENDS bls_unit_test dkg_unit_test
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMENT "Run all BLS and DKG tests"
		)
endif()

install(TARGETS bls DESTINATION lib)

install(TARGETS dkg_keygen DESTINATION bin)

install(TARGETS sign_bls DESTINATION bin)

install(TARGETS verify_bls DESTINATION bin)

