#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"

namespace libBLS {
namespace algebra {

std::pair< FqElement, FqElement > parseHint( const std::string& hint );

std::pair< G1Point, std::string > hashtoG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr );

}  // namespace algebra
}  // namespace libBLS
