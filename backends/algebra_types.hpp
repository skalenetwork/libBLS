#pragma once

#include "./interface/init.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#endif

namespace libBLS {

namespace algebra {

#ifdef MCL
#else
typedef libff::alt_bn128_Fr FrBackendType;
typedef libff::alt_bn128_Fq FqBackendType;
typedef libff::alt_bn128_Fq2 Fq2BackendType;
typedef libff::alt_bn128_G2 G2BackendType;
typedef libff::alt_bn128_G1 G1BackendType;
typedef libff::alt_bn128_GT GTBackendType;

#endif

constexpr size_t HASH_SIZE = 32;
constexpr size_t MAX_FIELD_ELEMENT_SIZE_BYTES = 32;

// base for field element representation when converting to / from string
enum class Base : std::size_t {
    DEC = 10,
    HEXA = 16,
};
}  // namespace algebra

// allow libBLS users to use from libBLS namespace directly
using Base = algebra::Base;
using algebra::initCurve;
using algebra::MAX_FIELD_ELEMENT_SIZE_BYTES;

}  // namespace libBLS