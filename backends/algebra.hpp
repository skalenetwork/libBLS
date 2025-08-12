#pragma once

#include "./interface/field/FqElement.hpp"
#include "./interface/field/FrScalar.hpp"
#include "./interface/functions/bls.hpp"
#include "./interface/functions/core.hpp"
#include "./interface/functions/threshold_encryption.hpp"
#include "./interface/group/G1Point.hpp"
#include "./interface/group/G2Point.hpp"
#include "./interface/group/GTElement.hpp"
#include "./interface/init.hpp"
#include "algebra_types.hpp"


namespace libBLS {

// TODO - should name this Public Key size bytes - exposed API does not need to use / know
// algebraic internals
constexpr size_t G1_SIZE_BYTES = algebra::G1Point::SIZE_BYTES;
constexpr size_t G2_SIZE_BYTES = algebra::G2Point::SIZE_BYTES;

}  // namespace libBLS