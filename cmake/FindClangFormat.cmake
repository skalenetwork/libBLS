# Find Clang format
#
#
if( ( NOT DEFINED CLANG_FORMAT_BIN_NAME ) OR ( "${CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        #
        #set(CLANG_FORMAT_BIN_NAME clang-format)
        #
        unset( CLANG_FORMAT_FOUND )
        unset( CLANG_FORMAT_BIN_NAME )
        set( VARIANTS_OF_CLANG_FORMAT_BIN_NAME clang-format-6.0 clang-format-7.0 clang-format-8.0 clang-format )
        foreach( CLANG_FORMAT_WALK_VAR IN LISTS VARIANTS_OF_CLANG_FORMAT_BIN_NAME )
                execute_process( COMMAND bash -c "which ${CLANG_FORMAT_WALK_VAR}" OUTPUT_VARIABLE CLANG_FORMAT_BIN_NAME )
                if( ( DEFINED CLANG_FORMAT_BIN_NAME ) AND ( NOT "${CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
                        string(STRIP ${CLANG_FORMAT_BIN_NAME} CLANG_FORMAT_BIN_NAME)
                        set( CLANG_FORMAT_FOUND "1" )
                        break()
                endif()
        endforeach()
        unset( CLANG_FORMAT_WALK_VAR )
        if( ( NOT DEFINED CLANG_FORMAT_BIN_NAME ) OR ( "${CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
                message( INFO " - Failed to find clang-format executable")
        else()
                message( INFO " - Found clang-format executable: ${CLANG_FORMAT_BIN_NAME}")
        endif()
else()
        message( INFO " - Using externally specified clang-format executable: ${CLANG_FORMAT_BIN_NAME}")
endif()
if( ( NOT DEFINED CLANG_FORMAT_BIN_NAME ) OR ( "${CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        unset( CLANG_FORMAT_FOUND )
        unset( CLANG_FORMAT )
        unset( CLANG_FORMAT_BIN )
        unset( CLANG_FORMAT_BIN_NAME )
else()
        set( CLANG_FORMAT_FOUND "1" )
        set( CLANG_FORMAT     "${CLANG_FORMAT_BIN_NAME}" )
        set( CLANG_FORMAT_BIN "${CLANG_FORMAT_BIN_NAME}" )
endif()

# if custom path check there first
if( CLANG_FORMAT_ROOT_DIR )
    find_program(CLANG_FORMAT_BIN
        NAMES
        ${CLANG_FORMAT_BIN_NAME}
        PATHS
        "${CLANG_FORMAT_ROOT_DIR}"
        NO_DEFAULT_PATH)
endif()

find_program( CLANG_FORMAT_BIN NAMES ${CLANG_FORMAT_BIN_NAME} )

include( FindPackageHandleStandardArgs )
FIND_PACKAGE_HANDLE_STANDARD_ARGS( CLANG_FORMAT DEFAULT_MSG CLANG_FORMAT_BIN )

mark_as_advanced( CLANG_FORMAT_BIN )

if( ( NOT DEFINED CLANG_FORMAT_BIN_NAME ) OR ( "${CLANG_FORMAT_BIN_NAME}" STREQUAL "" ) )
        message( INFO " - clang-format not found and not specified - will skip setting up format targets" )
else()
        # A CMake script to find all source files and setup clang-format targets for them
        include( clang-format )
endif()
