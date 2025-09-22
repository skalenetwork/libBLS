cmake_minimum_required(VERSION 3.5)
project(libbls_te_bench CXX)

message("Building threshold encryption benchmarks")

# Configure header exposing backend string into the bench binary
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/backend_info.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/backend_info.hpp 
    @ONLY # only replace variables of the form @VAR@.
)

function(add_bench name main_source)
  add_executable(${name}
    ${main_source}
    ${TEST_DIR}/utils.cpp
  )

  target_compile_features(${name} PRIVATE cxx_std_20)

  target_include_directories(${name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}           # for bench_util.hpp and local includes
    ${CMAKE_CURRENT_BINARY_DIR}           # for generated headers like backend_info.hpp
    ${CMAKE_SOURCE_DIR}/threshold_encryption
    ${CMAKE_SOURCE_DIR}
  )

  # Link order: put highest-level libs first
  target_link_libraries(${name} PRIVATE
    te
    bls
    backend
  )
  
  add_test(NAME ${name} COMMAND ${name})
endfunction()

######### Add Benchmarks #########

add_bench(bench_te   bench_te.cpp)
add_bench(bench_bls  bench_bls.cpp)
