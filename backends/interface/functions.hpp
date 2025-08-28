#pragma once

#include "backends/interface/group/G1Point.hpp"
#include "backends/interface/group/G2Point.hpp"
#include "backends/interface/group/GTElement.hpp"

#include <utility>

namespace libBLS::algebra {

constexpr size_t BASE_HEXA = 16;
constexpr size_t BASE_DEC = 10;


// -------------------- Backend Specific -------------------- //
// All functions below need to be re-implemented for each backend
// in the corresponding functions.cpp file

GTElement pairing( const G1Point& g1, const G2Point& g2 );

// TODO - check why there is ^ operator and also this power function
FrScalar power( const FrScalar& fr, size_t exponent );

// Exponentiation using a big integer
FqElement power( const FqElement& fq, const std::string& exponent );

void normalizeYCoordinate( FqElement& element );

FqElement hashToFq( const std::array< uint8_t, 32 >& hash_byte_arr );

// -------------------- Backend Agnostic -------------------- //
// These functions are implemented in functions.cpp and should
// work for any backend

std::pair< FqElement, FqElement > parseHint( const std::string& _hint );

std::pair< G1Point, std::string > hashToG1withHint(
    const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::array< uint8_t, 32 >& hash_byte_arr );

G1Point hashToG1( const std::string& message );

std::vector< FrScalar > lagrangeCoeffs( const std::vector< size_t >& idx, size_t t );


}  // namespace libBLS::algebra
