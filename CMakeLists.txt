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
	# Set DEPS_INSTALL_ROOT based on the platform
	if (EMSCRIPTEN)
		set( DEPS_INSTALL_ROOT "${DEPS_SOURCES_ROOT}/deps_inst/wasm32-emscripten")
    else()
        set( DEPS_INSTALL_ROOT "${DEPS_SOURCES_ROOT}/deps_inst/x86_or_x64")
    endif()
endif()
message(INFO "---- DEPS_INSTALL_ROOT in BLS is: ${DEPS_INSTALL_ROOT}")

include_directories( "${DEPS_INSTALL_ROOT}/include" ${CMAKE_BINARY_DIR}/deps/include )
link_directories( "${DEPS_INSTALL_ROOT}/lib" )
set( CMAKE_PREFIX_PATH "${DEPS_INSTALL_ROOT}" )

set( LIBBLS_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory" )
list( APPEND CMAKE_MODULE_PATH ${LIBBLS_CMAKE_DIR} )

find_library( CRYPTOPP_LIBRARY NAMES "crypto" PATHS "${DEPS_INSTALL_ROOT}/lib" )

option(LIBBLS_BUILD_TESTS "Build tests" ON)
option(LIBBLS_BUILD_WITH_FPIC "Build with -fPIC" OFF)
option(LIBBLS_BUILD_UTILS "Build utils" ON)
option(LIBBLS_BUILD_BENCHMARKS "Build benchmarks" ON)

# No need to build tests and benchmarks with emscripten
if (EMSCRIPTEN)
  set(LIBBLS_BUILD_TESTS       OFF CACHE BOOL "Build tests"       FORCE)
  set(LIBBLS_BUILD_BENCHMARKS  OFF CACHE BOOL "Build benchmarks"  FORCE)
endif()

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

if(LIBBLS_BUILD_TESTS)
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


#######################################
# Sanitizers
#######################################

option(ENABLE_SANITIZERS "Enable ASan + LSan" OFF)
if (ENABLE_SANITIZERS)
	message(STATUS "**********************")
	message(STATUS "*** ENABLE_SANITIZERS is ON ***")
	message(STATUS "**********************")
	set(CMAKE_CXX_FLAGS "-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -g ${CMAKE_CXX_FLAGS}")
	set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address -fsanitize=leak ${CMAKE_EXE_LINKER_FLAGS}")
endif()


set( CLANG_FORMAT_EXCLUDE_PATTERNS
    ${CMAKE_BINARY_DIR}
    ${DEPS_SOURCES_ROOT}
)
include( BlsFindClangFormat )

set( TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/test/")
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
	dkg/DKGTEWrapper.cpp
	dkg/DKGTESecret.cpp
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

set(DEPS_LIB_DIR "${DEPS_INSTALL_ROOT}/lib")

# Only set FOLLY_STATIC_LIBS if not building with emscripten
if (EMSCRIPTEN)
	set(FOLLY_STATIC_LIBS "")
else()
	set(FOLLY_STATIC_LIBS
		"${DEPS_LIB_DIR}/libfolly.a"
		"${DEPS_LIB_DIR}/libglog.a"
		"${DEPS_LIB_DIR}/libgflags.a"
		"${DEPS_LIB_DIR}/libfmt.a"
		"${DEPS_LIB_DIR}/libdouble-conversion.a"
		"${DEPS_LIB_DIR}/libevent.a"
		"${DEPS_LIB_DIR}/libboost_context.a"
	)
endif()


include_directories(${DEPS_INSTALL_ROOT}/include)
link_directories(${DEPS_INSTALL_ROOT}/lib)

# TMP fix for emscripten
# Build utils exactly once
add_library(common_utils STATIC tools/utils.cpp tools/utils.h)
# SYSTEM - silence warnings from third-party code
target_include_directories(common_utils SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(common_utils
  PRIVATE
    backend
    ${CRYPTOPP_LIBRARY}
    ${FOLLY_STATIC_LIBS}
)

add_subdirectory(backends)

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


target_include_directories(bls SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls PUBLIC backend PRIVATE ${CRYPTOPP_LIBRARY} common_utils)

add_subdirectory(threshold_encryption)

if (LIBBLS_BUILD_UTILS)
	# Helper function for utils setup
	function(add_bls_tool name source)
		add_executable(${name} ${source})
		target_include_directories(${name} SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

		if (EMSCRIPTEN)
			target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
			set_target_properties(${name} PROPERTIES LINK_FLAGS "-s -fwasm-exceptions")
		endif()

		target_link_libraries(${name} PRIVATE bls ${CRYPTOPP_LIBRARY} boost_program_options)
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

if(LIBBLS_BUILD_TESTS)
	# Helper function to add tests
	function(add_bls_test name source)
		set(extra_libs ${ARGN})  # Capture any extra libraries passed as arguments

		add_executable(${name} ${source})
		target_include_directories(${name} SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

		if (EMSCRIPTEN)
			target_compile_options(${name} PRIVATE -s DISABLE_EXCEPTION_CATCHING=1)
			set_target_properties(${name} PROPERTIES LINK_FLAGS "-s -fwasm-exceptions")
		else()
			target_compile_options(${name} PRIVATE -Wno-format-overflow)
		endif()

		target_link_libraries(${name} PRIVATE 
			bls 
			${CRYPTOPP_LIBRARY} 
			boost_program_options 
			${extra_libs}
			${FOLLY_STATIC_LIBS}
		)
		add_test(NAME ${name} COMMAND ${name})
	endfunction()

    add_bls_test(bls_unit_test test/unit_tests_bls.cpp)
    add_bls_test(dkg_unit_test test/unit_tests_dkg.cpp)
    add_bls_test(bls_test test/test_bls.cpp)

    # utils_unit_test requires an extra library 'te'
    add_bls_test(utils_unit_test test/unit_tests_utils.cpp te)

    # Special case for dkg_attack (no compile options)
    add_executable(dkg_attack test/dkg_attack.cpp)
    target_include_directories(dkg_attack SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(dkg_attack PRIVATE bls ${CRYPTOPP_LIBRARY} boost_program_options)
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

if (LIBBLS_BUILD_BENCHMARKS)
	add_subdirectory(benchmarks)
endif()

# Build python threshold_encryption shared library
add_library(skale_te_python SHARED python/tepython.cpp)
target_include_directories(skale_te_python PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# Link against te (Threshold Encryption), bls, common_utils and other dependencies
# Use --whole-archive to ensure all symbols from static libs are included in the shared lib
if(APPLE)
    target_link_libraries(skale_te_python PRIVATE 
        -Wl,-force_load,$<TARGET_FILE:te>
        -Wl,-force_load,$<TARGET_FILE:bls>
        -Wl,-force_load,$<TARGET_FILE:common_utils>
        backend ${FOLLY_STATIC_LIBS} ${CRYPTOPP_LIBRARY})
    # Explicitly add dependencies for Apple builds because they are hidden inside linker flags
    add_dependencies(skale_te_python te bls common_utils)
else()
    target_link_libraries(skale_te_python PRIVATE 
        -Wl,--whole-archive te bls common_utils -Wl,--no-whole-archive 
        backend ${FOLLY_STATIC_LIBS} ${CRYPTOPP_LIBRARY})
endif()
