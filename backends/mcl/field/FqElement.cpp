#ifdef MCL

#include "backends/interface/field/FqElement.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include "tools/utils.h"
#include <gmpxx.h>
#include <iostream>

namespace libBLS::algebra {

// -------------------- Private Methods -------------------- //

mpz_class FqElement::toMpzClass() const {
    std::string s = value.getStr( 10 );  // base 10 decimal string
    mpz_class t;
    if ( mpz_set_str( t.get_mpz_t(), s.c_str(), 10 ) != 0 ) {
        THROW( "mpz_set_str failed" );
    }
    return t;
}

FqBackendType FqElement::fromMpzClass( const mpz_class& m ) {
    FqBackendType x( m.get_str( 10 ).c_str(), 10 );
    return x;
}

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
    return toByteArrayDefault();
}

FqElement FqElement::fromString( const std::string& str, Base base ) {
    FqBackendType x;
    trySettingFieldWithString( x, str, base );
    return FqElement( x );
}

FqElement FqElement::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    return fromBytesDefault( bytes );
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