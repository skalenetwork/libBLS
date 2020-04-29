# Find Clang format
#
#
if( ( NOT DEFINED BLS_CLANG_FORMAT_BIN_NAME ) OR ( "${BLS_CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        #
        #set(BLS_CLANG_FORMAT_BIN_NAME clang-format)
        #
        unset( BLS_CLANG_FORMAT_FOUND )
        unset( BLS_CLANG_FORMAT_BIN_NAME )
        set( VARIANTS_OF_BLS_CLANG_FORMAT_BIN_NAME clang-format-6.0 ) # clang-format-7.0 clang-format-8.0 clang-format
        foreach( BLS_CLANG_FORMAT_WALK_VAR IN LISTS VARIANTS_OF_BLS_CLANG_FORMAT_BIN_NAME )
                execute_process( COMMAND bash -c "which ${BLS_CLANG_FORMAT_WALK_VAR}" OUTPUT_VARIABLE BLS_CLANG_FORMAT_BIN_NAME )
                if( ( DEFINED BLS_CLANG_FORMAT_BIN_NAME ) AND ( NOT "${BLS_CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
                        string(STRIP ${BLS_CLANG_FORMAT_BIN_NAME} BLS_CLANG_FORMAT_BIN_NAME)
                        set( BLS_CLANG_FORMAT_FOUND "1" )
                        break()
                endif()
        endforeach()
        unset( BLS_CLANG_FORMAT_WALK_VAR )
        if( ( NOT DEFINED BLS_CLANG_FORMAT_BIN_NAME ) OR ( "${BLS_CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
                message( INFO " - Failed to find clang-format executable")
        else()
                message( INFO " - Found clang-format executable: ${BLS_CLANG_FORMAT_BIN_NAME}")
        endif()
else()
        message( INFO " - Using externally specified clang-format executable: ${BLS_CLANG_FORMAT_BIN_NAME}")
endif()
if( ( NOT DEFINED BLS_CLANG_FORMAT_BIN_NAME ) OR ( "${BLS_CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        unset( BLS_CLANG_FORMAT_FOUND )
        unset( BLS_CLANG_FORMAT )
        unset( BLS_CLANG_FORMAT_BIN )
        unset( BLS_CLANG_FORMAT_BIN_NAME )
else()
        set( BLS_CLANG_FORMAT_FOUND "1" )
        set( BLS_CLANG_FORMAT     "${BLS_CLANG_FORMAT_BIN_NAME}" )
        set( BLS_CLANG_FORMAT_BIN "${BLS_CLANG_FORMAT_BIN_NAME}" )
endif()

# if custom path check there first
if( BLS_CLANG_FORMAT_ROOT_DIR )
    find_program(BLS_CLANG_FORMAT_BIN
        NAMES
        ${BLS_CLANG_FORMAT_BIN_NAME}
        PATHS
        "${BLS_CLANG_FORMAT_ROOT_DIR}"
        NO_DEFAULT_PATH)
endif()

find_program( BLS_CLANG_FORMAT_BIN NAMES ${BLS_CLANG_FORMAT_BIN_NAME} )

include( FindPackageHandleStandardArgs )
FIND_PACKAGE_HANDLE_STANDARD_ARGS( BLS_CLANG_FORMAT DEFAULT_MSG BLS_CLANG_FORMAT_BIN )

mark_as_advanced( BLS_CLANG_FORMAT_BIN )

if( ( NOT DEFINED BLS_CLANG_FORMAT_BIN_NAME ) OR ( "${BLS_CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        message( INFO " - clang-format not found and not specified - will skip setting up format targets" )
else()
        # A CMake script to find all source files and setup clang-format targets for them
        include( bls-clang-format )
endif()
