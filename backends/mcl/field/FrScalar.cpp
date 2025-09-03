#ifdef MCL

#include "backends/interface/field/FrScalar.hpp"
#include "../utils.hpp"
#include <tools/utils.h>

namespace libBLS {
namespace algebra {

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
    std::vector< uint8_t > vec( SIZE_BYTES );
    // returns in little endian
    value.serialize( vec.data(), vec.size() );
    std::reverse( vec.begin(), vec.end() );  // convert to big endian
    return vec;
}

// TODO check if there is a more efficient way to do this
std::array< uint8_t, FrScalar::SIZE_BYTES > FrScalar::toByteArray() const {
    std::array< uint8_t, SIZE_BYTES > arr;
    // returns in little endian
    value.serialize( arr.data(), arr.size() );
    std::reverse( arr.begin(), arr.end() );  // convert to big endian
    return arr;
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
    FrBackendType field_elem;
    // assume input is in big endian - convert to little endian
    std::array< uint8_t, SIZE_BYTES > bytes_copy = bytes;
    std::reverse( bytes_copy.begin(), bytes_copy.end() );

    if ( !field_elem.deserialize( bytes_copy.data(), bytes_copy.size() ) ) {
        throw ThresholdUtils::IncorrectInput( "Invalid byte array for FrScalar" );
    }
    return FrScalar( field_elem );
}

FrScalar FrScalar::fromBytes( const std::vector< uint8_t >& bytes ) {
    FrBackendType field_elem;
    // assume input is in big endian - convert to little endian
    std::vector< uint8_t > bytes_copy = bytes;
    std::reverse( bytes_copy.begin(), bytes_copy.end() );

    if ( !field_elem.deserialize( bytes_copy.data(), bytes_copy.size() ) ) {
        throw ThresholdUtils::IncorrectInput( "Invalid byte vector for FrScalar" );
    }
    return FrScalar( field_elem );
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