#pragma once

#include "../gt.hpp"
#include "../g1.hpp"
#include "../g2.hpp"

namespace libBLS {
namespace algebra {

std::vector< FrScalar > lagrangeCoeffs(const std::vector< size_t >& idx, size_t t );

} // namespace algebra
} // namespace libBLS

