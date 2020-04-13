# A CMake script to find all source files and setup clang-format targets for them

# Find all source files
set(BLS_CLANG_FORMAT_CXX_FILE_EXTENSIONS ${BLS_CLANG_FORMAT_CXX_FILE_EXTENSIONS} *.cpp *.h *.cxx *.hxx *.hpp *.cc *.ipp)
file(GLOB_RECURSE BLS_ALL_SOURCE_FILES ${BLS_CLANG_FORMAT_CXX_FILE_EXTENSIONS})

# Don't include some common build folders
set(BLS_CLANG_FORMAT_EXCLUDE_PATTERNS ${BLS_CLANG_FORMAT_EXCLUDE_PATTERNS} "/CMakeFiles/" "cmake")

# get all project files file
foreach (BLS_EXCLUDE_PATTERN ${BLS_CLANG_FORMAT_EXCLUDE_PATTERNS})
    list(FILTER BLS_ALL_SOURCE_FILES EXCLUDE REGEX ${BLS_EXCLUDE_PATTERN})
endforeach()

add_custom_target( bls-format
    COMMENT "Running clang-format to change BLS files"
    COMMAND ${CLANG_FORMAT_BIN}
    -style=file
    -i
    ${BLS_ALL_SOURCE_FILES}
)


add_custom_target( bls-format-check
    COMMENT "Checking clang-format changes in BLS"
    # Use ! to negate the result for correct output
    COMMAND !
    ${CLANG_FORMAT_BIN}
    -style=file
    -output-replacements-xml
    ${BLS_ALL_SOURCE_FILES}
    | grep -q "replacement offset"
)

# Get the path to this file
get_filename_component(_clangcheckpath ${CMAKE_CURRENT_LIST_FILE} PATH)
# have at least one here by default
set(BLS_CHANGED_FILE_EXTENSIONS ".cpp")
foreach(EXTENSION ${BLS_CLANG_FORMAT_CXX_FILE_EXTENSIONS})
    set(BLS_CHANGED_FILE_EXTENSIONS "${BLS_CHANGED_FILE_EXTENSIONS},${EXTENSION}" )
endforeach()

set(BLS_EXCLUDE_PATTERN_ARGS)
foreach(BLS_EXCLUDE_PATTERN ${BLS_CLANG_FORMAT_EXCLUDE_PATTERNS})
    list(APPEND BLS_EXCLUDE_PATTERN_ARGS "--exclude=${BLS_EXCLUDE_PATTERN}")
endforeach()

# call the script to chech changed files in git
add_custom_target( bls-format-check-changed
    COMMENT "Checking changed BLS files in git"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND ${_clangcheckpath}/../scripts/clang-format-check-changed.py 
    --file-extensions \"${BLS_CHANGED_FILE_EXTENSIONS}\"
    ${BLS_EXCLUDE_PATTERN_ARGS}
    --clang-format-bin ${CLANG_FORMAT_BIN}
)



