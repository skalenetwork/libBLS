#include "backends/interface/field/FqElement.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/WrapperCore.hpp"
#include <gmpxx.h>

namespace libBLS {
namespace algebra {

FqElement::FqElement() : WrapperCore( libff::alt_bn128_Fq::zero() ) {}

FqElement::FqElement( uint64_t x ) : WrapperCore( libff::alt_bn128_Fq( x ) ) {}

// -------------------- Serialization / Deserialization Methods -------------------- //

std::string FqElement::toString( Base base ) const {
    return fieldElementToString( value, static_cast< size_t >( base ) );
}

std::array< uint8_t, FqElement::SIZE_BYTES > FqElement::toByteArray() const {
    return fieldElementToBytesArray( value );
}

FqElement FqElement::fromString( const std::string& str, Base base ) {
    switch ( base ) {
    case Base::HEXA:
        // let it go to default case
    case Base::DEC:
        return FqElement( libff::alt_bn128_Fq( str.c_str() ) );
    default:
        throw ThresholdUtils::IncorrectInput( "Unsupported base for FqElement conversion" );
    }
}

FqElement FqElement::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    return FqElement( bytesToFieldElement< libff::alt_bn128_Fq >( bytes ) );
}

// -------------------- Operator Overloads -------------------- //

FqElement FqElement::operator+( const FqElement& other ) const {
    return FqElement( value + other.value );
}

FqElement FqElement::operator-( const FqElement& other ) const {
    return FqElement( value - other.value );
}

FqElement FqElement::operator*( const FqElement& other ) const {
    return FqElement( value * other.value );
}

FqElement& FqElement::operator+=( const FqElement& other ) {
    value += other.value;
    return *this;
}

FqElement FqElement::operator^( const unsigned long pow ) const {
    return FqElement( value ^ pow );
}

FqElement& FqElement::operator*=( const FqElement& other ) {
    value *= other.value;
    return *this;
}

bool FqElement::operator==( const FqElement& other ) const {
    return value == other.value;
}

bool FqElement::operator!=( const FqElement& other ) const {
    return value != other.value;
}

// -------------------- Static Methods -------------------- //

FqElement FqElement::random() {
    return FqElement( libff::alt_bn128_Fq::random_element() );
}

FqElement FqElement::fromHash( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr ) {
    libff::bigint< libff::alt_bn128_q_limbs > from_hex;

    std::vector< uint8_t > hex( 2 * HASH_SIZE );
    for ( size_t i = 0; i < HASH_SIZE; ++i ) {
        hex[2 * i] = static_cast< int >( hash_byte_arr.at( i ) ) / 16;
        hex[2 * i + 1] = static_cast< int >( hash_byte_arr.at( i ) ) % 16;
    }
    mpn_set_str( from_hex.data, hex.data(), 2 * HASH_SIZE, 16 );

    libff::alt_bn128_Fq ret_val( from_hex );

    return algebra::FqElement( ret_val );
}

template <>
FqElement WrapperCore< FqBackendType, FqElement >::zero() {
    return FqElement( libff::alt_bn128_Fq::zero() );
}

template <>
FqElement WrapperCore< FqBackendType, FqElement >::one() {
    return FqElement( libff::alt_bn128_Fq::one() );
}

}  // namespace algebra
}  // namespace libBLS