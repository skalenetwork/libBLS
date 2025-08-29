#ifdef LIBFF

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>

#include "../utils.hpp"
#include "backends/interface/field/FrScalar.hpp"

namespace libBLS::algebra {

mpz_class FrScalar::toMpzClass() const {
    mpz_class t;
    value.as_bigint().to_mpz( t.get_mpz_t() );
    return t;
}

FrBackendType FrScalar::fromMpzClass( const mpz_class& m ) {
    FrBackendType field_elem( m.get_mpz_t() );
    return field_elem;
}

template <>
FrScalar Field< FrBackendType, FrScalar >::zero() {
    return FrScalar( libff::alt_bn128_Fr::zero() );
}

template <>
FrScalar Field< FrBackendType, FrScalar >::one() {
    return FrScalar( libff::alt_bn128_Fr::one() );
}

template <>
bool Field< FrBackendType, FrScalar >::isZero() const {
    return value.is_zero();
}

template <>
bool Field< FrBackendType, FrScalar >::isOne() const {
    return value == libff::alt_bn128_Fr::one();
}


FrScalar::FrScalar() {
    value = libff::alt_bn128_Fr::zero();
}

FrScalar::FrScalar( const size_t n ) : Field( libff::alt_bn128_Fr( n ) ) {}

FrScalar FrScalar::inverse() const {
    return FrScalar( value.inverse() );
}

// ---------- Serialization  ----------- //

std::vector< uint8_t > FrScalar::toByteVector() const {
    return toByteVectorDefault();
}

std::array< uint8_t, FrScalar::SIZE_BYTES > FrScalar::toByteArray() const {
    return toByteArrayDefault();
}

std::string FrScalar::toString( Base base ) const {
    return toStringDefault( base );
}

// ---------- Deserialization ----------- //

FrScalar FrScalar::fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
    return fromBytesDefault( bytes );
}

FrScalar FrScalar::fromBytes( const std::vector< uint8_t >& bytes ) {
    if ( bytes.size() != SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Invalid byte vector size for FrScalar" );
    }

    std::array< uint8_t, SIZE_BYTES > frBytes;
    std::copy( bytes.begin(), bytes.end(), frBytes.begin() );

    return fromBytes( frBytes );
}

FrScalar FrScalar::fromString( const std::string& str, Base base ) {
    switch ( base ) {
    case Base::HEXA: {
        auto decStr = convertHexToDec( str );
        return FrScalar( libff::alt_bn128_Fr( decStr.c_str() ) );
    }
    case Base::DEC:
        return FrScalar( libff::alt_bn128_Fr( str.c_str() ) );
    default:
        throw ThresholdUtils::IncorrectInput( "Unsupported base for FrScalar conversion" );
    }
}

// -------------------- Static Methods -------------------- //

FrScalar FrScalar::random() {
    return FrScalar( libff::alt_bn128_Fr::random_element() );
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

}  // namespace libBLS::algebra

#endif  // LIBFF