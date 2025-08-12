# backends/CMakeLists.txt

# Backend selection via cache so parent can override
option(USE_LIBFF "Use libff backend" ON)
option(USE_MCL "Use mcl backend" OFF)

if(USE_LIBFF AND USE_MCL)
  message(FATAL_ERROR "Cannot enable both USE_LIBFF and USE_MCL. Choose only one.")
endif()

if(NOT USE_LIBFF AND NOT USE_MCL)
  message(STATUS "No backend selected, defaulting to libff")
  set(USE_LIBFF ON)
endif()

# Set backend name
if(USE_LIBFF)
    set(BACKEND_NAME "libff")                           # used as the directory name
    set(BACKEND_LIB "ff")                               # used as the library name when linking
    set(BACKEND_DEPS ${GMPXX_LIBRARY} ${GMP_LIBRARY})   # extra dependencies that may be used by the backend
    add_compile_definitions(USE_LIBFF)
elseif(USE_MCL)
    set(BACKEND_NAME "mcl")
    set(BACKEND_LIB "mcl")
    set(BACKEND_DEPS "")
    add_compile_definitions(USE_MCL)
    # add more backends below if needed
endif()


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
    "${BACKEND_BASE_DIR}/interface/functions"
    "${BACKEND_BASE_DIR}/interface/test"

    # backend specific includes
    "${BACKEND_SRC_DIR}"
    "${BACKEND_SRC_DIR}/field"
    "${BACKEND_SRC_DIR}/group"
    "${BACKEND_SRC_DIR}/functions"
    "${BACKEND_SRC_DIR}/test"
)

# Common backend source files
set(BACKEND_SRC_NAMES
    # field scalars
    "field/FqElement.cpp"
    "field/Fq2Element.cpp"
    "field/FrScalar.cpp"

    # groups
    "group/G1Point.cpp"
    "group/G2Point.cpp"
    "group/GTElement.cpp"

    # base curve initialization
    "init.cpp"

    # functions
    "functions/bls.cpp"
    "functions/core.cpp"
    "functions/threshold_encryption.cpp"

    # testing utils
    "test/FqElementTestAccessor.cpp"
)

set(BACKEND_SOURCES "")
foreach(file ${BACKEND_SRC_NAMES})
    list(APPEND BACKEND_SOURCES "${BACKEND_SRC_DIR}/${file}")
endforeach()

add_library(backend STATIC ${BACKEND_SOURCES})

target_include_directories(backend PUBLIC
    "${BACKEND_BASE_DIR}/.."  # This allows "backends/interface/..." includes
    "${BACKEND_BASE_DIR}/interface"
)

# following libs should not be exposed to any other part of the system
target_link_libraries(backend PRIVATE 
    ${BACKEND_LIB}
    ${BACKEND_DEPS}
    ${CRYPTOPP_LIBRARY}  
)
