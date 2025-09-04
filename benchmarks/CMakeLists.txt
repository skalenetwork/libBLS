cmake_minimum_required(VERSION 3.20)
project(libbls_te_bench CXX)

message("Building threshold encryption benchmarks")

if(USE_MCL)
    set(LIBBLS_BACKEND "mcl")
elseif(USE_LIBFF)
    set(LIBBLS_BACKEND "libff")
else() # set MCL by default
    set(LIBBLS_BACKEND "mcl")
endif()

# Configure header exposing backend string into the bench binary
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/backend_info.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/backend_info.hpp 
    @ONLY # only replace variables of the form @VAR@.
)

add_executable(te_bench
    bench_te.cpp
    bench_bls.cpp
    ${TEST_DIR}/utils.cpp
    bench_util.hpp
)

target_include_directories(te_bench PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} # for backend_info.hpp
    ${CMAKE_SOURCE_DIR}/threshold_encryption
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(te_bench PRIVATE
    backend
    te
    bls
)

# Optimization flags for timing
if (MSVC)
    target_compile_options(te_bench PRIVATE /O2 /DNDEBUG)
else()
    target_compile_options(te_bench PRIVATE -O3 -DNDEBUG)
endif()

target_compile_features(te_bench PRIVATE cxx_std_20)

# Make the bench easy to run via `ctest` if desired
add_test(NAME te_bench COMMAND te_bench)