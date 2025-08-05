#pragma once

#include "gt.hpp"
#include "g1.hpp"
#include "g2.hpp"

namespace libBLS {
namespace algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

inline GTElement pairing(const G1Point& g1, const G2Point& g2);

inline FrScalar power( const FrScalar& fr, int exponent );

} // namespace algebra
} // namespace libBLS

