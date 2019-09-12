include(ExternalProject)

get_filename_component(PBC_PREFIX "${CMAKE_BINARY_DIR}/deps"
                       REALPATH BASE_DIR "${CMAKE_BINARY_DIR}")

set(PBC_LIBRARY "${PBC_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}pbc${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(PBC_INCLUDE_DIR "${PBC_PREFIX}/include/pbc")

ExternalProject_Add( pbc
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../pbc
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND libtoolize --force && aclocal && autoheader && automake --force-missing
                      --add-missing && autoconf && ./configure --with-pic --enable-static
                      --disable-shared --prefix=${PBC_PREFIX}
    BUILD_COMMAND make install
)
