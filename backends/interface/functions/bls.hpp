#pragma once

#include "../gt.hpp"
#include "../g1.hpp"
#include "../g2.hpp"

namespace libBLS {
namespace algebra {

std::pair< FqElement, FqElement > parseHint(const std::string& hint );

std::pair< G1Point, std::string > hashtoG1withHint(const std::array< uint8_t, 32 >& hash_byte_arr );

} // namespace algebra
} // namespace libBLS

