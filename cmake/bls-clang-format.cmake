# A CMake script to find all source files and setup clang-format targets for them

# Find all source files
set(CLANG_FORMAT_CXX_FILE_EXTENSIONS ${CLANG_FORMAT_CXX_FILE_EXTENSIONS} *.cpp *.h *.cxx *.hxx *.hpp *.cc *.ipp)
file(GLOB_RECURSE ALL_SOURCE_FILES ${CLANG_FORMAT_CXX_FILE_EXTENSIONS})

# Don't include some common build folders
set(CLANG_FORMAT_EXCLUDE_PATTERNS ${CLANG_FORMAT_EXCLUDE_PATTERNS} "/CMakeFiles/" "cmake")

# get all project files file
foreach (EXCLUDE_PATTERN ${CLANG_FORMAT_EXCLUDE_PATTERNS})
    list(FILTER ALL_SOURCE_FILES EXCLUDE REGEX ${EXCLUDE_PATTERN})
endforeach()

add_custom_target(bls-format
    COMMENT "Running clang-format to change files"
    COMMAND ${BLS_CLANG_FORMAT_BIN} -style=file -i ${ALL_SOURCE_FILES}
)


add_custom_target(bls-format-check
    COMMENT "Checking clang-format changes"
    # Use ! to negate the result for correct output
    COMMAND ! ${BLS_CLANG_FORMAT_BIN} -style=file -output-replacements-xml ${ALL_SOURCE_FILES} | grep -q "replacement offset"
)

# Get the path to this file
get_filename_component(_clangcheckpath ${CMAKE_CURRENT_LIST_FILE} PATH)
# have at least one here by default
set(CHANGED_FILE_EXTENSIONS ".cpp")
foreach(EXTENSION ${CLANG_FORMAT_CXX_FILE_EXTENSIONS})
    set(CHANGED_FILE_EXTENSIONS "${CHANGED_FILE_EXTENSIONS},${EXTENSION}" )
endforeach()

set(EXCLUDE_PATTERN_ARGS)
foreach(EXCLUDE_PATTERN ${CLANG_FORMAT_EXCLUDE_PATTERNS})
    list(APPEND EXCLUDE_PATTERN_ARGS "--exclude=${EXCLUDE_PATTERN}")
endforeach()

# call the script to chech changed files in git
add_custom_target(bls-format-check-changed
    COMMENT "Checking changed files in git"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMAND ${_clangcheckpath}/../scripts/clang-format-check-changed.py 
    --file-extensions \"${CHANGED_FILE_EXTENSIONS}\"
    ${EXCLUDE_PATTERN_ARGS}
    --clang-format-bin ${BLS_CLANG_FORMAT_BIN}
)

