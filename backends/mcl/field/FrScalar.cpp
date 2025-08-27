#ifdef MCL

#include "../utils.hpp"
#include "backends/interface/field/FrScalar.hpp"
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
    if (value.isZero()) {
        throw ThresholdUtils::IncorrectInput( "Cannot invert zero in FrScalar" );
    }
    FrBackendType inv;
    FrBackendType::inv(inv, value);
    return FrScalar( inv );
}

// ---------- Serialization  ----------- //

std::vector< uint8_t > FrScalar::toByteVector() const {
    return fieldElementToBytes( value );
}

std::array< uint8_t, FrScalar::SIZE_BYTES > FrScalar::toByteArray() const {
    return fieldElementToByteArray( value );
}

std::string FrScalar::toString( Base base ) const {
    return value.getStr(toIoBase(base));
}

// ---------- Deserialization ----------- //

FrScalar FrScalar::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    return FrScalar( bytesToFieldElement< FrBackendType >( bytes ) );
}

FrScalar FrScalar::fromBytes( const std::vector< uint8_t >& bytes ) {
    return FrScalar(bytesToFieldElement< FrBackendType >( bytes ));
}

FrScalar FrScalar::fromString( const std::string& str, Base base ) {
    FrBackendType x;
    trySettingFieldWithString(x, str, base);
    return FrScalar(x);
}

// -------------------- Static Methods -------------------- //

FrScalar FrScalar::random() {
    FrBackendType rand_val;
    do { rand_val.setByCSPRNG(); } while (rand_val.isZero());
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

#endif // MCL