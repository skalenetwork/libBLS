cmake_minimum_required( VERSION 3.5.1 )

project( libBLS )

set( HUNTER_ENABLED OFF )

option( BUILD_TESTS "Build tests" ON )

if( BUILD_TESTS )
	enable_testing()
endif()

option( COVERAGE "Build with code coverage support" OFF )
if( COVERAGE )
	message( STATUS "**********************" )
	message( STATUS "*** COVERAGE is ON ***" )
	message( STATUS "**********************" )
	add_compile_options( -g --coverage )

	set( CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage" )
	set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage" )

	set( CMAKE_SHARED_LINKER_FLAGS "--coverage ${CMAKE_SHARED_LINKER_FLAGS}" )
	set( CMAKE_EXE_LINKER_FLAGS "--coverage ${CMAKE_EXE_LINKER_FLAGS}" )
endif()


set( sourses_bls
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
		third_party/cryptlite/base64.cpp
		)
set( headers_bls
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
		third_party/json.hpp
		third_party/cryptlite/sha256.h
		third_party/cryptlite/sha1.h
		third_party/cryptlite/hmac.h
		third_party/cryptlite/base64.h
		)

set(PROJECT_VERSION 0.4.0)
add_definitions(-DBLS_VERSION=${PROJECT_VERSION})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -fPIC -std=c++17 -Wno-error=parentheses -Wno-error=char-subscripts -Wno-error=unused-variable -Wno-error=unused-parameter -Wno-error=int-in-bool-context")

include_directories(${CMAKE_BINARY_DIR}/deps/include ${GMP_INCLUDE_DIR})
link_directories(${CMAKE_BINARY_DIR}/deps/lib)

include(deps/ProjectGMP.cmake)

add_library(bls ${sourses_bls} ${headers_bls})
target_compile_options( bls PUBLIC -Wno-error=sign-compare -Wno-error=reorder -Wno-error=unused-but-set-variable )

find_package( Boost REQUIRED program_options system )
find_package(OpenSSL REQUIRED)

if ((DEFINED BLS_WITH_SECP256K1_INCLUDE_DIR) AND (DEFINED BLS_WITH_SECP256K1_LIBRARY_DIR))
	add_dependencies(bls secp256k1)
else()
	include(deps/ProjectSecp256k1.cmake)
	set(BLS_WITH_SECP256K1_INCLUDE_DIR ${CMAKE_BINARY_DIR}/deps/include)
	set(BLS_WITH_SECP256K1_LIBRARY_DIR ${CMAKE_BINARY_DIR}/deps/lib)
	add_dependencies(bls secp256k1)
endif()

include_directories(${BLS_WITH_SECP256K1_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})
link_directories(${BLS_WITH_SECP256K1_LIBRARY_DIR})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set(WITH_PROCPS OFF)
endif()

if( (DEFINED BLS_WITH_FF_INCLUDE_DIR) AND (DEFINED BLS_WITH_FF_LIBRARY_DIR))
	add_dependencies(bls libff)
else()
	add_subdirectory(libff)
	set(BLS_WITH_FF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libff)
	set(BLS_WITH_FF_LIBRARY_DIR ${CMAKE_BINARY_DIR}/libff/libff)
	add_dependencies(bls ff)
endif()

message(INFO " - Using final BLS INC=${BLS_WITH_FF_INCLUDE_DIR}")
message(INFO " - Using final BLS LIB=${BLS_WITH_FF_LIBRARY_DIR}")
include_directories(${BLS_WITH_FF_INCLUDE_DIR})
link_directories(${BLS_WITH_FF_LIBRARY_DIR})

set(BLS_INCLUDE_DIRS
		${CMAKE_CURRENT_SOURCE_DIR}
		${CMAKE_CURRENT_SOURCE_DIR}/bls
		${CMAKE_CURRENT_SOURCE_DIR}/deps/include
		${CMAKE_CURRENT_SOURCE_DIR}/libff
		${BLS_WITH_FF_INCLUDE_DIR}
		PARENT_SCOPE
		)

add_dependencies(bls gmp)
target_include_directories(bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bls PRIVATE ff ${GMPXX_LIBRARY} ${GMP_LIBRARY})

add_subdirectory(threshold_encryption)

add_executable(dkg_keygen tools/dkg_key_gen.cpp)
target_include_directories(dkg_keygen PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dkg_keygen PRIVATE bls Boost::program_options)

add_executable(dkg_glue tools/dkg_glue.cpp)
target_include_directories(dkg_glue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dkg_glue PRIVATE bls Boost::program_options)

add_executable( sign_bls tools/sign_bls.cpp )
target_include_directories( sign_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( sign_bls PRIVATE bls Boost::program_options )

add_executable( bls_glue tools/bls_glue.cpp )
target_include_directories( bls_glue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( bls_glue PRIVATE bls Boost::program_options )

add_executable( verify_bls tools/verify_bls.cpp )
target_include_directories( verify_bls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
target_link_libraries( verify_bls PRIVATE bls Boost::program_options )

if( BUILD_TESTS )
	add_executable( bls_unit_test test/unit_tests_bls.cpp )
	target_include_directories( bls_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
	target_link_libraries( bls_unit_test PRIVATE bls )

	add_test( NAME bls_tests COMMAND bls_unit_test )

	add_executable( dkg_unit_test test/unit_tests_dkg.cpp )
	target_include_directories( dkg_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
	target_link_libraries( dkg_unit_test PRIVATE bls )
	add_test( NAME dkg_tests COMMAND dkg_unit_test )

	add_executable( bls_test test/test_bls.cpp )
	target_include_directories( bls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} )
	target_link_libraries( bls_test PRIVATE bls )
	add_test( NAME bls_test COMMAND bls_test )

	add_custom_target(all_bls_tests
			COMMAND ./bls_unit_test
			COMMAND ./dkg_unit_test
			COMMAND ./bls_test
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
