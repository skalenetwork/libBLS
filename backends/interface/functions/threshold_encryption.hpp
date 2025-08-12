#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"

namespace libBLS {
namespace algebra {

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t );

}  // namespace algebra
}  // namespace libBLS
