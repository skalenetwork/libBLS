#include "backends/interface/group/G1Point.hpp"
#include "../utils.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"
#include <tools/utils.h>
#include <array>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

G1Point::G1Point() {
    value = libff::alt_bn128_G1::zero();
}

G1Point::G1Point( const FqElement& x, const FqElement& y ) {
    value.X = x.value;
    value.Y = y.value;
    value.Z = libff::alt_bn128_Fq::one();
}

G1Point::G1Point( const FqElement& x, const FqElement& y, const FqElement& z ) {
    value.X = x.value;
    value.Y = y.value;
    value.Z = z.value;
}

void G1Point::toAffineCoordinates() {
    value.to_affine_coordinates();
}

bool G1Point::isZero() const {
    return value.is_zero();
}

bool G1Point::isWellFormed() const {
    return value.is_well_formed();
}

bool G1Point::isInGroup() const {
    return libff::alt_bn128_modulus_r * value == libff::alt_bn128_G1::zero();
}

bool G1Point::isValid() const {
    return !isZero() && isWellFormed() && isInGroup();
}

void G1Point::validate() const {
    if ( isZero() ) {
        throw ThresholdUtils::IsNotWellFormed( "Point is zero" );
    }
    if ( !isWellFormed() ) {
        throw ThresholdUtils::IsNotWellFormed( "Point is not well formed" );
    }
    if ( !isInGroup() ) {
        throw ThresholdUtils::IsNotWellFormed( "Point is not on the group" );
    }
}

FqElement G1Point::getX() const {
    return FqElement( value.X );
}

FqElement G1Point::getY() const {
    return FqElement( value.Y );
}

// --------------------- Static Methods -------------------- //

G1Point G1Point::random() {
    return G1Point( libff::alt_bn128_G1::random_element() );
}

G1Point G1Point::fromBytes( const std::array< uint8_t, G1Point::SIZE_BYTES >& bytes ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > currentField;

    algebra::G1Point ret;
    ret.value.Z = libff::alt_bn128_Fq::one();

    const uint8_t* source = bytes.data();

    // Get X
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.value.X = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += MAX_FIELD_ELEMENT_SIZE_BYTES;

    // Get Y
    std::memcpy( currentField.data(), source, MAX_FIELD_ELEMENT_SIZE_BYTES );
    ret.value.Y = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );

    return ret;
}

G1Point G1Point::fromString( const std::string& str, Base base ) {
    if ( base != Base::HEXA ) {
        throw ThresholdUtils::IncorrectInput(
            "G1Point currently can only be constructed from HEXA string" );
    }

    const size_t stringSize = 128;
    const size_t elementStringSize = 64;

    if ( str.size() != stringSize ) {
        throw ThresholdUtils::IncorrectInput( "Wrong string size to convert to G1" );
    }

    algebra::G1Point ret;

    ret.value.Z = libff::alt_bn128_Fq::one();
    ret.value.X = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 0 * elementStringSize, elementStringSize ) )
            .c_str() );
    ret.value.Y = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 1 * elementStringSize, elementStringSize ) )
            .c_str() );

    return ret;
}


// TODO - this function should either be part og functions/bls, or we should put the toHash also in
// this class
G1Point G1Point::fromHash( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr ) {
    libff::alt_bn128_Fq x1( FqElement::fromHash( hash_byte_arr ).value );
    libff::alt_bn128_G1 result;

    while ( true ) {
        libff::alt_bn128_Fq y1_sqr = x1 ^ 3;
        y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

        libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

        if ( euler == libff::alt_bn128_Fq::one() ||
             euler == libff::alt_bn128_Fq::zero() ) {  // if y1_sqr is a square
            result.X = x1;
            libff::alt_bn128_Fq temp_y = y1_sqr.sqrt();

            mpz_class y, y_neg;
            temp_y.as_bigint().to_mpz( y.get_mpz_t() );
            // convert -y in Fq first, then convert to mpz
            ( -temp_y ).as_bigint().to_mpz( y_neg.get_mpz_t() );

            if ( y < y_neg ) {
                temp_y = -temp_y;
            }

            result.Y = temp_y;
            break;
        } else {
            x1 = x1 + 1;
        }
    }
    result.Z = libff::alt_bn128_Fq::one();

    return G1Point( result );
}

G1Point G1Point::fromHash( const std::string& message ) {
    auto hash_bytes_arr = std::array< uint8_t, HASH_SIZE >();

    uint64_t bin_len;
    if ( !ThresholdUtils::hex2carray( message.c_str(), &bin_len, hash_bytes_arr.data() ) ) {
        throw std::runtime_error( "Invalid hash" );
    }

    return fromHash( hash_bytes_arr );
}

template <>
G1Point WrapperCore< G1BackendType, G1Point >::zero() {
    return G1Point( libff::alt_bn128_G1::zero() );
}

template <>
G1Point WrapperCore< G1BackendType, G1Point >::one() {
    return G1Point( libff::alt_bn128_G1::one() );
}

// -------------------- Operator Overloads -------------------- //

G1Point G1Point::operator+( const G1Point& other ) const {
    return G1Point( value + other.value );
}

G1Point G1Point::operator-( const G1Point& other ) const {
    return G1Point( value - other.value );
}

bool G1Point::operator==( const G1Point& other ) const {
    return value == other.value;
}

bool G1Point::operator!=( const G1Point& other ) const {
    return value != other.value;
}


G1Point operator*( const FrScalar& scalar, const G1Point& point ) {
    return G1Point( scalar.value * point.value );
}

// -------------------- Helper methods for PointSerializer -------------------- //

void G1Point::forEachAffineComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto affine = value;
    affine.to_affine_coordinates();
    fn( FqElement( affine.X ), 0 );
    fn( FqElement( affine.Y ), 1 );
}

void G1Point::forEachProjectiveComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto projective = value;
    fn( FqElement( value.X ), 0 );
    fn( FqElement( value.Y ), 1 );
    fn( FqElement( value.Z ), 2 );
}

}  // namespace algebra
}  // namespace libBLS
