# backends/CMakeLists.txt

################# May Change to add new backends #################

# Backend selection via cache so parent can override
option(USE_LIBFF "Use libff backend" OFF)
option(USE_MCL "Use mcl backend" OFF)

if(USE_LIBFF AND USE_MCL)
  message(FATAL_ERROR "Cannot enable both USE_LIBFF and USE_MCL. Choose only one.")
endif()

if(NOT USE_LIBFF AND NOT USE_MCL)
  message(STATUS "No backend selected, defaulting to mcl")
  set(USE_MCL ON)
endif()

if(USE_LIBFF)
  find_library( GMP_LIBRARY NAMES "gmp" PATHS "${DEPS_INSTALL_ROOT}/lib" )
  find_library( GMPXX_LIBRARY NAMES "gmpxx" PATHS "${DEPS_INSTALL_ROOT}/lib" )
  set(BACKEND_NAME libff)                           # used as the directory name
  set(BACKEND_LIB ff)                               # used as the library name when linking
  set(BACKEND_COMPILE_OPTIONS "")
  set(BACKEND_DEPS ${GMPXX_LIBRARY} ${GMP_LIBRARY})
  set(BACKEND_DEFINE LIBFF)
elseif(USE_MCL)
  set(BACKEND_NAME mcl)
  set(BACKEND_LIB mcl)
  set(BACKEND_DEPS "")
  set(BACKEND_COMPILE_OPTIONS 
    MCL_FP_BIT=256
    MCL_FR_BIT=256
  )
  set(BACKEND_DEFINE MCL)
  # add more backends below if needed
endif()

# make the selected backend visible to the rest of the system
set(BACKEND_DEFINE "${BACKEND_DEFINE}" CACHE STRING "Selected libBLS backend" FORCE)
message("Using backend: ${BACKEND_NAME}")

############### DO NOT CHANGE BELOW THIS LINE ###############

# Directories - assumes all backends have the same common
# base file names, and folder structure - only differs by
# folder name - which should be the backend name

set(BACKEND_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(BACKEND_SRC_DIR "${BACKEND_BASE_DIR}/${BACKEND_NAME}")
set(INTERFACE_DIRS 
    # interface directories common to all backends
    "${BACKEND_BASE_DIR}"
    "${BACKEND_BASE_DIR}/interface"
    "${BACKEND_BASE_DIR}/interface/field"
    "${BACKEND_BASE_DIR}/interface/group"
    "${BACKEND_BASE_DIR}/interface/test"

    # backend specific includes
    "${BACKEND_SRC_DIR}"
    "${BACKEND_SRC_DIR}/field"
    "${BACKEND_SRC_DIR}/group"
    "${BACKEND_SRC_DIR}/test"
)

# Backend-specific source files (under ${backend}/...)
set(BACKEND_SPECIFIC_SOURCES
    # field scalars
    "field/FqElement.cpp"
    "field/Fq2Element.cpp"
    "field/FrScalar.cpp"

    # groups
    "group/G1Point.cpp"
    "group/G2Point.cpp"
    "group/GTElement.cpp"

    # functions
    "functions.cpp"

    # base curve initialization
    "init.cpp"

    # testing utils
    "test/FqElementTestAccessor.cpp"
)

# Global sources common to all backends
set(BACKEND_SOURCES 
  "${BACKEND_BASE_DIR}/interface/functions.cpp"
  "${BACKEND_BASE_DIR}/interface/curve_contract_altbn128.cpp"
  ${TOOLS_DIR}/utils.cpp
) 


# merge backend-specific sources with global sources
foreach(file ${BACKEND_SPECIFIC_SOURCES})
    list(APPEND BACKEND_SOURCES "${BACKEND_SRC_DIR}/${file}")
endforeach()

add_library(backend STATIC ${BACKEND_SOURCES})

target_include_directories(backend PUBLIC
    "${BACKEND_BASE_DIR}/.."  # This allows "backends/interface/..." includes
    "${BACKEND_BASE_DIR}/interface"
)

target_compile_definitions(backend PUBLIC
    ${BACKEND_DEFINE}
    ${BACKEND_COMPILE_OPTIONS}
)

# following libs should not be exposed to any other part of the system
target_link_libraries(backend PUBLIC 
    ${BACKEND_LIB}
    ${BACKEND_DEPS}
    ${CRYPTOPP_LIBRARY} # only needed for tests because tests use utils.cpp. Need to refactor this
)


######### Backend Unit Tests #########

if(BUILD_TESTS)

  set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/../test)
  set(TOOLS_DIR ${CMAKE_CURRENT_LIST_DIR}/../tools)

  function(add_backend_test name source_rel)
    add_executable(${name}
      ${TEST_DIR}/${source_rel}
      ${TOOLS_DIR}/utils.cpp
    )

    target_include_directories(${name} PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${THIRD_PARTY_DIR}
      ${TEST_DIR}
    )

    target_compile_options(${name} PRIVATE
      $<$<CXX_COMPILER_ID:GNU,Clang>:-Wno-format-overflow>
    )

    target_link_libraries(${name} PRIVATE backend)

    # Register test with the full path to the built binary (portable)
    add_test(NAME ${name} COMMAND $<TARGET_FILE:${name}>)
  endfunction()

  add_backend_test(backend_unit_test unit_tests_backend.cpp)
endif()
