cmake_minimum_required(VERSION 3.5.1)

project(bls)

option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
	enable_testing()
endif()

option( COVERAGE "Build with code coverage support" OFF )
if( COVERAGE )
    message( STATUS "**********************" )
    message( STATUS "*** COVERAGE is ON ***" )
    message( STATUS "**********************" )
    add_compile_options( -g --coverage )
    #
    set( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage" )
    #
    set( CMAKE_SHARED_LINKER_FLAGS "--coverage ${CMAKE_SHARED_LINKER_FLAGS}" )
    set( CMAKE_EXE_LINKER_FLAGS "--coverage ${CMAKE_EXE_LINKER_FLAGS}" )
endif()

set(sourses
    bls/bls.cpp
    dkg/dkg.cpp
    third_party/base64.cpp
)

set(headers
    bls/bls.h
    dkg/dkg.h
    third_party/sha256.h
    third_party/sha1.h
    third_party/hmac.h
    third_party/base64.h
)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -fPIC -std=c++11 -Wno-error=parentheses -Wno-error=char-subscripts")

include_directories(${CMAKE_BINARY_DIR}/deps/include /usr/include/python3.5m)

link_directories(${CMAKE_BINARY_DIR}/deps/lib usr/lib/python3.5)

include_directories(${CMAKE_BINARY_DIR}/deps/include ${GMP_INCLUDE_DIR})

link_directories(${CMAKE_BINARY_DIR}/deps/lib)

include(deps/ProjectGMP.cmake)
include(deps/ProjectSecp256k1.cmake)
include(deps/ProjectLibFF.cmake)

add_library(bls ${sourses} ${headers})
add_dependencies(bls gmp libff secp256k1)
target_include_directories(bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls PRIVATE ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

if (BUILD_TESTS)
	add_executable(bls_unit_test test/unit_tests_bls.cpp)
	target_include_directories(bls_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(bls_unit_test PRIVATE bls ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})


	add_test(NAME bls_tests COMMAND bls_unit_test)

	add_executable(dkg_unit_test test/unit_tests_dkg.cpp)
	target_include_directories(dkg_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(dkg_unit_test PRIVATE bls ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})


	add_test(NAME dkg_tests COMMAND dkg_unit_test)
endif()
