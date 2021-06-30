cmake_minimum_required(VERSION 3.5.1)

set( CMAKE_CXX_STANDARD 17 )

project(libBLS)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
        message(FATAL_ERROR "Require at least gcc-7.0")
    endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "*** Have SIZEOF void * = 8, so 64-bit")
else ()
    message(FATAL_ERROR "*** SIZEOF void * != 8, so not 64-bit - libBLS supports only 64-bit")
endif ()

if( NOT DEFINED DEPS_INSTALL_ROOT )
    set( DEPS_SOURCES_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/deps")
    set( DEPS_INSTALL_ROOT "${DEPS_SOURCES_ROOT}/deps_inst/x86_or_x64")
endif()
message(INFO "---- DEPS_INSTALL_ROOT in BLS is: ${DEPS_INSTALL_ROOT}")

include_directories( "${DEPS_INSTALL_ROOT}/include" ${CMAKE_BINARY_DIR}/deps/include )
link_directories( "${DEPS_INSTALL_ROOT}/lib" )
set( CMAKE_PREFIX_PATH "${DEPS_INSTALL_ROOT}" )

set( LIBBLS_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory" )
list( APPEND CMAKE_MODULE_PATH ${LIBBLS_CMAKE_DIR} )

find_library( GMP_LIBRARY NAMES "gmp" PATHS "${DEPS_INSTALL_ROOT}/lib" )
find_library( GMPXX_LIBRARY NAMES "gmpxx" PATHS "${DEPS_INSTALL_ROOT}/lib" )

set( HUNTER_ENABLED OFF )

option(BUILD_TESTS "Build tests" ON)
option(BUILD_WITH_FPIC "Build with -fPIC" OFF)

if(BUILD_TESTS)
	enable_testing()
endif()

option(COVERAGE "Build with code coverage support" OFF)
if(COVERAGE)
	message(STATUS "**********************")
	message(STATUS "*** COVERAGE is ON ***")
	message(STATUS "**********************")
	add_compile_options(-g --coverage)

	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage")

	set(CMAKE_SHARED_LINKER_FLAGS "--coverage ${CMAKE_SHARED_LINKER_FLAGS}")
	set(CMAKE_EXE_LINKER_FLAGS "--coverage ${CMAKE_EXE_LINKER_FLAGS}")
endif()

set( CLANG_FORMAT_EXCLUDE_PATTERNS
    ${CMAKE_BINARY_DIR}
    ${DEPS_SOURCES_ROOT}
    )
include( BlsFindClangFormat )

set(sourses_bls
		bls/bls.cpp
		bls/BLSPrivateKeyShare.cpp
		bls/BLSPrivateKey.cpp
		bls/BLSPublicKeyShare.cpp
		bls/BLSPublicKey.cpp
		bls/BLSSignature.cpp
		bls/BLSSigShare.cpp
		bls/BLSSigShareSet.cpp
		bls/BLSutils.cpp
		dkg/dkg.cpp
		dkg/DKGBLSWrapper.cpp
		dkg/DKGBLSSecret.cpp
		third_party/cryptlite/base64.cpp
		)

set(headers_bls
		libBLS.h
		bls/bls.h
		bls/BLSPrivateKeyShare.h
		bls/BLSPrivateKey.h
		bls/BLSPublicKeyShare.h
		bls/BLSPublicKey.h
		bls/BLSSignature.h
		bls/BLSSigShare.h
		bls/BLSSigShareSet.h
		bls/BLSutils.h
		dkg/dkg.h
		dkg/DKGBLSWrapper.h
		dkg/DKGBLSSecret.h
		third_party/json.hpp
		third_party/cryptlite/sha256.h
		third_party/cryptlite/sha1.h
		third_party/cryptlite/hmac.h
		third_party/cryptlite/base64.h
		)

set(PROJECT_VERSION 0.1.1)
add_definitions(-DBLS_VERSION=${PROJECT_VERSION})
if ( APPLE )
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wparentheses -Wunused -Wunreachable-code -Wextra -fPIC -std=c++17")
else()
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -Wparentheses -Wunused -Wunreachable-code -Wextra -Wno-error=int-in-bool-context -fPIC -std=c++17")
endif()

include_directories(${CMAKE_BINARY_DIR}/deps/include)
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

add_library(bls ${sourses_bls} ${headers_bls})

include_directories(${Boost_INCLUDE_DIRS})


if( SKALE_HAVE_BOOST_FROM_HUNTER )
  set( BOOST_LIBS_4_BLS Boost::program_options )
else()
  set( BOOST_LIBS_4_BLS boost_program_options )
endif()

set (WITH_PROCPS OFF)

set(BLS_INCLUDE_DIRS
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/bls
		${DEPS_SOURCES_ROOT}
		${DEPS_INSTALL_ROOT}
		${CMAKE_CURRENT_SOURCE_DIR}/deps/include
		PARENT_SCOPE
		)

target_include_directories(bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls PRIVATE ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

add_subdirectory(threshold_encryption)

add_executable(dkg_keygen tools/dkg_key_gen.cpp)
target_include_directories(dkg_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(dkg_keygen PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(dkg_glue tools/dkg_glue.cpp)
target_include_directories(dkg_glue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dkg_glue PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(sign_bls tools/sign_bls.cpp)
target_include_directories(sign_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sign_bls PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(hash_g1 tools/hash_g1.cpp)
target_include_directories(hash_g1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hash_g1 PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(bls_glue tools/bls_glue.cpp)
target_include_directories(bls_glue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls_glue PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(verify_bls tools/verify_bls.cpp)
target_include_directories(verify_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(verify_bls PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

add_executable(generate_key_system tools/generate_key_system.cpp)
target_include_directories(generate_key_system PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(generate_key_system PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})


if(BUILD_TESTS)
	add_executable(bls_unit_test test/unit_tests_bls.cpp)
	target_include_directories(bls_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(bls_unit_test PRIVATE bls ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} ${BOOST_LIBS_4_BLS})

	add_test(NAME bls_tests COMMAND bls_unit_test)

	add_executable(dkg_unit_test test/unit_tests_dkg.cpp)
	target_include_directories(dkg_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(dkg_unit_test PRIVATE bls ff ${GMP_LIBRARY} ${GMPXX_LIBRARY} ${BOOST_LIBS_4_BLS})
  
	add_test(NAME dkg_tests COMMAND dkg_unit_test)

	add_executable(bls_test test/test_bls.cpp)
	target_include_directories(bls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(bls_test PRIVATE bls ff ${GMP_LIBRARY} ${GMPXX_LIBRARY} ${BOOST_LIBS_4_BLS})
  
	add_test(NAME bls_test COMMAND bls_test)

	add_executable(dkg_attack test/dkg_attack.cpp)
	target_include_directories(dkg_attack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
	target_link_libraries(dkg_attack PRIVATE bls ff ${GMP_LIBRARY} ${GMPXX_LIBRARY} ${BOOST_LIBS_4_BLS})

	add_test(NAME dkg_attack COMMAND dkg_attack)

	add_custom_target(all_bls_tests
			COMMAND ./bls_unit_test
			COMMAND ./dkg_unit_test
			COMMAND ./bls_test
                        COMMAND ./dkg_attack
			DEPENDS bls_unit_test dkg_unit_test
			WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			COMMENT "Run all BLS and DKG tests"
			)
endif()

if(NOT SKALE_SKIP_INSTALLING_DIRECTIVES)
	install( TARGETS bls DESTINATION lib )
	install( TARGETS dkg_keygen DESTINATION bin )
	install( TARGETS dkg_glue DESTINATION bin )
	install( TARGETS sign_bls DESTINATION bin )
	install( TARGETS bls_glue DESTINATION bin )
	install( TARGETS verify_bls DESTINATION bin )
endif()
