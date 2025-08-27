#ifdef LIBFF

#include "backends/interface/field/FqElement.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include <gmpxx.h>

namespace libBLS::algebra {

template <>
FqElement Field< FqBackendType, FqElement >::zero() {
    return FqElement( libff::alt_bn128_Fq::zero() );
}

template <>
FqElement Field< FqBackendType, FqElement >::one() {
    return FqElement( libff::alt_bn128_Fq::one() );
}

template <>
bool Field< FqBackendType, FqElement >::isZero() const {
    return value.is_zero();
}

template <>
bool Field< FqBackendType, FqElement >::isOne() const {
    return value == libff::alt_bn128_Fq::one();
}

FqElement FqElement::sqrt() const {
    libff::alt_bn128_Fq result = value.sqrt();
    return FqElement( result );
}

FqElement::FqElement() : Field( libff::alt_bn128_Fq::zero() ) {}

FqElement::FqElement( uint64_t x ) : Field( libff::alt_bn128_Fq( x ) ) {}

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

}  // namespace libBLS::algebra

#endif // LIBFF