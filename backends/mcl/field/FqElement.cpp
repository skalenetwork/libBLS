#ifdef MCL

#include "backends/interface/field/FqElement.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include "tools/utils.h"
#include <iostream>

namespace libBLS::algebra {

// -------------------- Template Specializations -------------------- //
// Should be placed at start of file - must be defined before any
// code that uses them

template <>
FqElement Field< FqBackendType, FqElement >::zero() {
    FqBackendType zero;
    zero.clear();
    return FqElement( zero );
}

template <>
FqElement Field< FqBackendType, FqElement >::one() {
    FqBackendType one;
    one.clear();
    one = FqBackendType::one();
    return FqElement( one );
}

template <>
bool Field< FqBackendType, FqElement >::isOne() const {
    return value.isOne();
}

template <>
bool Field< FqBackendType, FqElement >::isZero() const {
    return value.isZero();
}

// -------------------- Constructors -------------------- //

FqElement::FqElement() {
    FqBackendType zero;
    zero.clear();
    value = zero;
}

FqElement::FqElement( uint64_t x ) : Field( FqBackendType( x ) ) {}

// -------------------- Serialization / Deserialization Methods -------------------- //

uint64_t FqElement::toUlong() const {
    std::array< uint8_t, SIZE_BYTES > be{};
    const size_t n = value.serialize( be.data(), be.size() );  // big-endian canonical
    std::reverse( be.begin(), be.end() );                      // convert to little-endian
    uint64_t v = 0;
    const size_t start = n > 8 ? n - 8 : 0;  // take lowest 8 bytes
    for ( size_t i = start; i < n; ++i )
        v = ( v << 8 ) | be[i];
    return v;
}

std::string FqElement::toString( Base base ) const {
    constexpr size_t width = 2 * SIZE_BYTES;
    auto string = value.getStr( toIoBase( base ) );
    if ( base == Base::HEXA ) {
        if ( string.length() < width ) {
            string.insert( 0, width - string.length(), '0' );
        }
    }
    return string;
}

std::array< uint8_t, FqElement::SIZE_BYTES > FqElement::toByteArray() const {
    std::array< uint8_t, SIZE_BYTES > arr;
    // returns in little endian
    value.serialize( arr.data(), arr.size() );
    std::reverse( arr.begin(), arr.end() );  // convert to big endian
    return arr;
}

FqElement FqElement::fromString( const std::string& str, Base base ) {
    FqBackendType x;
    trySettingFieldWithString( x, str, base );
    return FqElement( x );
}

FqElement FqElement::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    FqBackendType field_elem;
    // assume input is in big endian - convert to little endian
    std::array< uint8_t, SIZE_BYTES > bytes_copy = bytes;
    std::reverse( bytes_copy.begin(), bytes_copy.end() );

    if ( !field_elem.deserialize( bytes_copy.data(), bytes_copy.size() ) ) {
        throw ThresholdUtils::IncorrectInput( "Invalid byte array for FqElement" );
    }
    return FqElement( field_elem );
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
    FqBackendType y;
    mcl::Fp::pow( y, value, pow );
    return FqElement( y );
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

FqElement FqElement::sqrt() const {
    FqBackendType y;
    mcl::Fp::squareRoot( y, value );
    return FqElement( y );
}

// -------------------- Static Methods -------------------- //

FqElement FqElement::random() {
    FqBackendType rand_val;
    do {
        rand_val.setByCSPRNG();
    } while ( rand_val.isZero() );
    return FqElement( rand_val );
}


}  // namespace libBLS::algebra

#endif  // MCL