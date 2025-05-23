cmake_minimum_required(VERSION 3.5)

set( CMAKE_CXX_STANDARD 20 )

project(libBLS)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
        message(FATAL_ERROR "Require at least gcc-7.0")
    endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "*** Have SIZEOF void * = 8, so 64-bit")
else ()
	if (EMSCRIPTEN)
		message(STATUS "*** SIZEOF void * = 4, while building with emscripten ")
	else()
		message(FATAL_ERROR "*** SIZEOF void * != 8, so not 64-bit - libBLS supports only 64-bit")
	endif()
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
find_library( CRYPTOPP_LIBRARY NAMES "crypto" PATHS "${DEPS_INSTALL_ROOT}/lib" )

option(BUILD_TESTS "Build tests" ON)
option(BUILD_WITH_FPIC "Build with -fPIC" OFF)
option(BUILD_UTILS "Build utils" ON)

option( BLS_PROFILING "Build for profiling" OFF )
if( SKALED_PROFILING OR CONSENSUS_PROFILING )
    set( BLS_PROFILING ON )
endif()
if( BLS_PROFILING )
    set( CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -pg" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg" )
    set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg" )
    set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg" )
endif()

if( CMAKE_BUILD_TYPE STREQUAL "Release" )
    set( CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -O3" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3" )
elseif( CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo" )
    set( CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -O3" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3" )
elseif( CMAKE_BUILD_TYPE STREQUAL "MinSizeRel" )
    set( CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Os" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os" )
elseif( CMAKE_BUILD_TYPE STREQUAL "Debug" )
    set( CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -O0" )
    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0" )
else()
	message( INFO "---- CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE} is not supported explicitly" )
endif()

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

set( TOOLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tools/")
set( DKG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dkg/")

set(sourses_bls
	bls/bls.cpp
	bls/BLSPrivateKeyShare.cpp
	bls/BLSPrivateKey.cpp
	bls/BLSPublicKeyShare.cpp
	bls/BLSPublicKey.cpp
	bls/BLSSignature.cpp
	bls/BLSSigShare.cpp
	bls/BLSSigShareSet.cpp
	dkg/dkg.cpp
	dkg/DKGBLSWrapper.cpp
	dkg/DKGBLSSecret.cpp
	third_party/cryptlite/base64.cpp
	tools/utils.cpp
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
	dkg/dkg.h
	dkg/DKGBLSWrapper.h
	dkg/DKGBLSSecret.h
	third_party/json.hpp
	third_party/cryptlite/sha256.h
	third_party/cryptlite/sha1.h
	third_party/cryptlite/hmac.h
	third_party/cryptlite/base64.h
	tools/utils.h
)

set(PROJECT_VERSION 0.2.0)
add_definitions(-DBLS_VERSION=${PROJECT_VERSION})
if ( APPLE )
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wparentheses -Wunused -Wno-error=deprecated-copy -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-error=maybe-uninitialized -Wunreachable-code -Wextra -fPIC -std=c++20")
else()
	if (EMSCRIPTEN)
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -std=c++20")
	else()
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wunreachable-code -Wextra -Wno-error=deprecated-copy -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-error=maybe-uninitialized -Wno-error=int-in-bool-context -fPIC -std=c++20")
		if( CMAKE_BUILD_TYPE STREQUAL "Debug" )
			set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wparentheses -Wunused -Wno-error=deprecated-copy -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-error=maybe-uninitialized" )
                else()
                    set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=deprecated-copy -Wno-error=unused-parameter -Wno-error=unused-variable -Wno-error=maybe-uninitialized" )
		endif()
	endif()
endif()

include_directories(${CMAKE_BINARY_DIR}/deps/include)
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

add_library(bls ${sourses_bls} ${headers_bls})

include_directories(${Boost_INCLUDE_DIRS})

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
target_link_libraries(bls PRIVATE ff ${CRYPTOPP_LIBRARY} ${GMPXX_LIBRARY} ${GMP_LIBRARY})

add_subdirectory(threshold_encryption)

if (BUILD_UTILS)
	# Helper function for utils setup
	function(add_bls_tool name source)
		add_executable(${name} ${source})
		target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

		if (EMSCRIPTEN)
			target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
			set_target_properties(${name} PROPERTIES LINK_FLAGS "-s DISABLE_EXCEPTION_CATCHING=1")
		endif()

		target_link_libraries(${name} PRIVATE bls ${CRYPTOPP_LIBRARY} ff ${GMPXX_LIBRARY} ${GMP_LIBRARY} boost_program_options)
	endfunction()

	# Add all tools using the function
	add_bls_tool(dkg_keygen tools/dkg_key_gen.cpp)
	add_bls_tool(dkg_glue tools/dkg_glue.cpp)
	add_bls_tool(sign_bls tools/sign_bls.cpp)
	add_bls_tool(hash_g1 tools/hash_g1.cpp)
	add_bls_tool(bls_glue tools/bls_glue.cpp)
	add_bls_tool(verify_bls tools/verify_bls.cpp)
	add_bls_tool(generate_key_system tools/generate_key_system.cpp)

endif()

if(BUILD_TESTS)
	# Helper function to add tests
	function(add_bls_test name source)
		set(extra_libs ${ARGN})  # Capture any extra libraries passed as arguments

		add_executable(${name} ${source})
		target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

		if (EMSCRIPTEN)
			target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
			set_target_properties(${name} PROPERTIES LINK_FLAGS "-s DISABLE_EXCEPTION_CATCHING=1")
		else()
			target_compile_options(${name} PRIVATE -Wno-format-overflow)
		endif()

		target_link_libraries(${name} PRIVATE bls ${CRYPTOPP_LIBRARY} ff ${GMP_LIBRARY} ${GMPXX_LIBRARY} boost_program_options ${extra_libs})
		add_test(NAME ${name} COMMAND ${name})
	endfunction()

    add_bls_test(bls_unit_test test/unit_tests_bls.cpp)
    add_bls_test(dkg_unit_test test/unit_tests_dkg.cpp)
    add_bls_test(bls_test test/test_bls.cpp)

    # utils_unit_test requires an extra library 'te'
    add_bls_test(utils_unit_test test/unit_tests_utils.cpp te)

    # Special case for dkg_attack (no compile options)
    add_executable(dkg_attack test/dkg_attack.cpp)
    target_include_directories(dkg_attack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(dkg_attack PRIVATE bls ${CRYPTOPP_LIBRARY} ff ${GMP_LIBRARY} ${GMPXX_LIBRARY} boost_program_options)
    add_test(NAME dkg_attack COMMAND dkg_attack)

	add_custom_target(all_bls_tests
			COMMAND ./bls_unit_test
			COMMAND ./dkg_unit_test
			COMMAND ./bls_test
			COMMAND ./utils_unit_test
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
