#include "backends/interface/group/G2Point.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

G2Point::G2Point() {
    value = libff::alt_bn128_G2::zero();
}

G2Point::G2Point( const Fq2Element& x, const Fq2Element& y, const Fq2Element& z ) {
    value.X.c0 = x.value.c0;
    value.X.c1 = x.value.c1;
    value.Y.c0 = y.value.c0;
    value.Y.c1 = y.value.c1;
    value.Z.c0 = z.value.c0;
    value.Z.c1 = z.value.c1;
}

void G2Point::toAffineCoordinates() {
    value.to_affine_coordinates();
}

// -------------------- Validation Methods -------------------- //

bool G2Point::isZero() const {
    return value.is_zero();
}

bool G2Point::isWellFormed() const {
    return value.is_well_formed();
}

bool G2Point::isInGroup() const {
    return libff::alt_bn128_G2::order() * value == libff::alt_bn128_G2::zero();
}

bool G2Point::isValid() const {
    return !isZero() && isWellFormed() && isInGroup();
}

void G2Point::validate() const {
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

// -------------------- Static Methods -------------------- //

G2Point G2Point::random() {
    return G2Point( libff::alt_bn128_G2::random_element() );
}

G2Point G2Point::fromBytes( const std::array< uint8_t, G2Point::SIZE_BYTES >& bytes ) {
    const size_t FQ_SIZE_BYTES = FqElement::SIZE_BYTES;
    std::array< uint8_t, FQ_SIZE_BYTES > currentField;

    algebra::G2Point ret;
    ret.value.Z = libff::alt_bn128_Fq2::one();

    const uint8_t* source = bytes.data();

    // Get x.c0
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.X.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get x.c1
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.X.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get y.c0
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.Y.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get y.c1
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.Y.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );

    return ret;
}

G2Point G2Point::fromBytes( const std::vector< uint8_t >& bytes ) {
    if ( bytes.size() != SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes" );
    }

    std::array< uint8_t, SIZE_BYTES > G2Bytes;
    std::copy( bytes.begin(), bytes.end(), G2Bytes.begin() );

    return fromBytes( G2Bytes );
}

G2Point G2Point::fromString( const std::string& str, Base base ) {
    if ( base != libBLS::Base::HEXA ) {
        throw ThresholdUtils::IncorrectInput(
            "G2Point is currently only supported to be built from hexadecimal base string" );
    }

    const size_t stringSize = 256;
    const size_t elementStringSize = 64;

    if ( str.size() != stringSize ) {
        throw ThresholdUtils::IncorrectInput( "Wrong string size to convert to G2" );
    }

    algebra::G2Point ret;

    ret.value.Z = libff::alt_bn128_Fq2::one();

    ret.value.X.c0 = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 0 * elementStringSize, elementStringSize ) )
            .c_str() );
    ret.value.X.c1 = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 1 * elementStringSize, elementStringSize ) )
            .c_str() );
    ret.value.Y.c0 = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 2 * elementStringSize, elementStringSize ) )
            .c_str() );
    ret.value.Y.c1 = libff::alt_bn128_Fq(
        ThresholdUtils::convertHexToDec( str.substr( 3 * elementStringSize, std::string::npos ) )
            .c_str() );

    return ret;
}

G2Point G2Point::fromString(
    const std::array< std::string, G2_NUM_COMPONENTS_AFFINE >& arr, Base base ) {
    algebra::G2Point ret;
    ret.value.Z = libff::alt_bn128_Fq2::one();

    switch ( base ) {
    case Base::HEXA:

        std::array< std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >, 4 > components;
        // convert from hexa to bytes
        for ( size_t i = 0; i < arr.size(); ++i ) {
            if ( arr[i].length() != MAX_FIELD_ELEMENT_SIZE_BYTES * 2 ) {
                throw ThresholdUtils::IncorrectInput( "wrong string length in public key share" );
            }
            // throws if cannot hexa is not valid
            components[i] = ThresholdUtils::hexCStringToBytesArray< MAX_FIELD_ELEMENT_SIZE_BYTES >(
                arr[i].c_str() );
        }

        ret.value.X.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( components[0] );
        ret.value.X.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( components[1] );
        ret.value.Y.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( components[2] );
        ret.value.Y.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( components[3] );
        break;
    case Base::DEC:
        ret.value.X.c0 = libff::alt_bn128_Fq( arr[0].c_str() );
        ret.value.X.c1 = libff::alt_bn128_Fq( arr[1].c_str() );
        ret.value.Y.c0 = libff::alt_bn128_Fq( arr[2].c_str() );
        ret.value.Y.c1 = libff::alt_bn128_Fq( arr[3].c_str() );
        break;
    default:
        throw ThresholdUtils::IncorrectInput( "Unsupported base" );
    }
    return ret;
}

G2Point G2Point::fromString( const std::vector< std::string >& arr, Base base ) {
    if ( arr.size() != G2_NUM_COMPONENTS_AFFINE ) {
        throw ThresholdUtils::IncorrectInput( "Wrong number of components in G2Point" );
    }
    std::array< std::string, G2_NUM_COMPONENTS_AFFINE > arrCopy;
    std::copy( arr.begin(), arr.end(), arrCopy.begin() );
    return fromString( arrCopy, base );
}

template <>
G2Point WrapperCore< G2BackendType, G2Point >::zero() {
    return G2Point( libff::alt_bn128_G2::zero() );
}

template <>
G2Point WrapperCore< G2BackendType, G2Point >::one() {
    return G2Point( libff::alt_bn128_G2::one() );
}

// -------------------- Operator Overloads -------------------- //

G2Point G2Point::operator+( const G2Point& other ) const {
    return G2Point( value + other.value );
}

G2Point G2Point::operator-( const G2Point& other ) const {
    return G2Point( value - other.value );
}

bool G2Point::operator==( const G2Point& other ) const {
    return value == other.value;
}

bool G2Point::operator!=( const G2Point& other ) const {
    return value != other.value;
}


G2Point operator*( const FrScalar& scalar, const G2Point& point ) {
    return scalar.value * point.value;
}

// -------------------- Helper methods for PointSerializer -------------------- //

void G2Point::forEachAffineComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto affine = value;
    affine.to_affine_coordinates();
    fn( FqElement( affine.X.c0 ), 0 );
    fn( FqElement( affine.X.c1 ), 1 );
    fn( FqElement( affine.Y.c0 ), 2 );
    fn( FqElement( affine.Y.c1 ), 3 );
}

void G2Point::forEachProjectiveComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto projective = value;
    fn( FqElement( value.X.c0 ), 0 );
    fn( FqElement( value.X.c1 ), 1 );
    fn( FqElement( value.Y.c0 ), 2 );
    fn( FqElement( value.Y.c1 ), 3 );
    fn( FqElement( value.Z.c0 ), 4 );
    fn( FqElement( value.Z.c1 ), 5 );
}

}  // namespace algebra
}  // namespace libBLS
