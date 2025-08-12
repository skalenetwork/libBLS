#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"
#include "tools/utils.h"

namespace libBLS {
namespace algebra {

GTElement pairing( const G1Point& g1, const G2Point& g2 ) {
    return libff::alt_bn128_ate_reduced_pairing( g1.value, g2.value );
}

}  // namespace algebra
}  // namespace libBLS
