#ifdef MCL

#include "backends/interface/field/FrScalar.hpp"
#include "../utils.hpp"
#include <tools/utils.h>

namespace libBLS {
namespace algebra {

mpz_class FrScalar::toMpzClass() const {
    std::string s = value.getStr( 10 );  // base 10 decimal string
    mpz_class t;
    if ( mpz_set_str( t.get_mpz_t(), s.c_str(), 10 ) != 0 ) {
        THROW( "mpz_set_str failed" );
    }
    return t;
}

FrBackendType FrScalar::fromMpzClass( const mpz_class& m ) {
    FrBackendType x( m.get_str( 10 ).c_str(), 10 );
    return x;
}

// -------------------- Template Specializations -------------------- //
// Should be placed at start of file - must be defined before any
// code that uses them

template <>
FrScalar Field< FrBackendType, FrScalar >::zero() {
    FrBackendType zero;
    zero.clear();
    return FrScalar( zero );
}

template <>
FrScalar Field< FrBackendType, FrScalar >::one() {
    FrBackendType one;
    one.clear();
    one = FrBackendType::one();
    return FrScalar( one );
}

template <>
bool Field< FrBackendType, FrScalar >::isZero() const {
    return value.isZero();
}

template <>
bool Field< FrBackendType, FrScalar >::isOne() const {
    return value.isOne();
}

// -------------------- Constructors -------------------- //

FrScalar::FrScalar() {
    value = FrBackendType();
    value.clear();
}

FrScalar::FrScalar( const size_t n ) : Field( FrBackendType( n ) ) {}

FrScalar FrScalar::inverse() const {
    if ( value.isZero() ) {
        throw ThresholdUtils::IncorrectInput( "Cannot invert zero in FrScalar" );
    }
    FrBackendType inv;
    FrBackendType::inv( inv, value );
    return FrScalar( inv );
}

// ---------- Serialization  ----------- //

// TODO check if there is a more efficient way to do this
std::vector< uint8_t > FrScalar::toByteVector() const {
    return toByteVectorDefault();
}

// TODO check if there is a more efficient way to do this
std::array< uint8_t, FrScalar::SIZE_BYTES > FrScalar::toByteArray() const {
    return toByteArrayDefault();
}

std::string FrScalar::toString( Base base ) const {
    constexpr size_t width = 2 * SIZE_BYTES;
    auto string = value.getStr( toIoBase( base ) );
    if ( base == Base::HEXA ) {
        if ( string.length() < width ) {
            string.insert( 0, width - string.length(), '0' );
        }
    }
    return string;
}

// ---------- Deserialization ----------- //

FrScalar FrScalar::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    return fromBytesDefault( bytes );
}

FrScalar FrScalar::fromBytes( const std::vector< uint8_t >& bytes ) {
    return fromBytesDefault( bytes );
}

FrScalar FrScalar::fromString( const std::string& str, Base base ) {
    FrBackendType x;
    trySettingFieldWithString( x, str, base );
    return FrScalar( x );
}

// -------------------- Static Methods -------------------- //

FrScalar FrScalar::random() {
    FrBackendType rand_val;
    do {
        rand_val.setByCSPRNG();
    } while ( rand_val.isZero() );
    return FrScalar( rand_val );
}

// -------------------- Operator Overloads -------------------- //

FrScalar FrScalar::operator+( const FrScalar& other ) const {
    return FrScalar( value + other.value );
}

FrScalar FrScalar::operator-( const FrScalar& other ) const {
    return FrScalar( value - other.value );
}

FrScalar FrScalar::operator-() const {
    return FrScalar( -value );
}

FrScalar FrScalar::operator*( const FrScalar& other ) const {
    return FrScalar( value * other.value );
}

FrScalar FrScalar::operator+=( const FrScalar& other ) {
    value += other.value;
    return *this;
}

FrScalar FrScalar::operator*=( const FrScalar& other ) {
    value *= other.value;
    return *this;
}

bool FrScalar::operator==( const FrScalar& other ) const {
    return value == other.value;
}

bool FrScalar::operator!=( const FrScalar& other ) const {
    return value != other.value;
}

}  // namespace algebra
}  // namespace libBLS

#endif  // MCL