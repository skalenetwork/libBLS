include(ExternalProject)
#include(GNUInstallDirs)

#set( prefix "${CMAKE_BINARY_DIR}/deps" )
get_filename_component( prefix  "${CMAKE_BINARY_DIR}/deps"
                       REALPATH BASE_DIR "${CMAKE_BINARY_DIR}" )


set( GMP_LIBRARY   "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gmp${CMAKE_STATIC_LIBRARY_SUFFIX}" )
set( GMPXX_LIBRARY "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gmpxx${CMAKE_STATIC_LIBRARY_SUFFIX}" )
set( GMP_INCLUDE_DIR "${prefix}/include")

ExternalProject_Add( gmp
    PREFIX ${prefix}
    DOWNLOAD_NAME gmp-6.1.2.tar.xz
    DOWNLOAD_NO_PROGRESS TRUE
    URL https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.xz
    URL_HASH SHA256=87b565e89a9a684fe4ebeeddb8399dce2599f9c9049854ca8c0dfbdea0e21912
    CMAKE_ARGS
	-DCMAKE_C_FLAGS=-Wno-pedantic
    #BUILD_BYPRODUCTS "${GMP_LIBRARY}"
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gmp-6.1.2
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gmp-6.1.2/configure --enable-cxx --enable-static --disable-shared --prefix=${prefix}
    BUILD_COMMAND ${MAKE}
)

