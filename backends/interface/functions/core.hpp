#pragma once

#include "../gt.hpp"
#include "../g1.hpp"
#include "../g2.hpp"

namespace libBLS {
namespace algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;

GTElement pairing(const G1Point& g1, const G2Point& g2);

#ifdef MCL
#else

template<typename Exponent>
FrScalar power( const FrScalar& fr, Exponent exponent ) {
    return libff::power(fr.value, exponent);
}

#endif


std::pair< FqElement, FqElement > parseHint(const std::string& hint );

} // namespace algebra
} // namespace libBLS

