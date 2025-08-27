#ifdef LIBFF

#include "backends/interface/group/G1Point.hpp"
#include "../utils.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"
#include <tools/utils.h>
#include <array>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

// -------------------- Template Specializations -------------------- //
// These must be defined before any code that uses them to avoid
// "specialization after instantiation" errors


template <>
const G1BackendType& Group< G1BackendType, G1Point, FqRefWrapper >::identityBackend() {
    static const G1BackendType identity = [] {
        return G1BackendType::zero();
    }();
    return identity;
}

template <>
const G1BackendType& Group< G1BackendType, G1Point, FqRefWrapper >::generatorBackend() {
    static const G1BackendType generator = [] {
        return G1BackendType::one();
    }();
    return generator;
}

template <>
bool Group< G1BackendType, G1Point, FqRefWrapper >::isIdentity() const {
    return value.is_zero();
}

template <>
bool Group< G1BackendType, G1Point, FqRefWrapper >::isGenerator() const {
    return value == libff::alt_bn128_G1::one();
}

// -------------------- Constructors -------------------- //

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

FqElement G1Point::getX() const {
    return FqElement( value.X );
}

FqElement G1Point::getY() const {
    return FqElement( value.Y );
}

template <>
void Group< G1BackendType, G1Point, FqRefWrapper >::toAffineCoordinates() {
    value.to_affine_coordinates();
}

template <>
bool Group< G1BackendType, G1Point, FqRefWrapper >::isWellFormed() const {
    return value.is_well_formed();
}

template <>
bool Group< G1BackendType, G1Point, FqRefWrapper >::isInGroup() const {
    return libff::alt_bn128_modulus_r * value == libff::alt_bn128_G1::zero();
}

template <>
FqRefWrapper Group< G1BackendType, G1Point, FqRefWrapper >::getXRef() {
    return FqRefWrapper( value.X );
}

template <>
FqRefWrapper Group< G1BackendType, G1Point, FqRefWrapper >::getYRef() {
    return FqRefWrapper( value.Y );
}

template <>
FqRefWrapper Group< G1BackendType, G1Point, FqRefWrapper >::getZRef() {
    return FqRefWrapper( value.Z );
}

// --------------------- Static Methods -------------------- //

template <>
G1Point Group< G1BackendType, G1Point, FqRefWrapper >::random() {
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
    ret.value.X = libff::alt_bn128_Fq(convertHexToDec( str.substr( 0 * elementStringSize, elementStringSize ) ).c_str() );
    ret.value.Y = libff::alt_bn128_Fq(convertHexToDec( str.substr( 1 * elementStringSize, elementStringSize ) ).c_str() );

    return ret;
}

G1Point G1Point::fromString(const std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE >& arr, Base base ) {
    algebra::G1Point ret;
    ret.value.Z = libff::alt_bn128_Fq::one();

    switch ( base ) {
    case Base::HEXA:
        ret.value.X = libff::alt_bn128_Fq(convertHexToDec( arr[0] ).c_str() );
        ret.value.Y = libff::alt_bn128_Fq(convertHexToDec( arr[1] ).c_str() );
        break;
    case Base::DEC:
        ret.value.X = libff::alt_bn128_Fq( arr[0].c_str() );
        ret.value.Y = libff::alt_bn128_Fq( arr[1].c_str() );
        break;
    default:
        throw ThresholdUtils::IncorrectInput( "Base not supported to build G1Point from string array" );
    }

    return G1Point( ret );
}


G1Point G1Point::fromString( const std::vector< std::string >& arr, Base base ) {
    if ( arr.size() != G1Point::NUM_COMPONENTS_AFFINE ) {
        throw ThresholdUtils::IncorrectInput( "Wrong array size to convert to G1Point" );
    }

    std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE > arrCopy;
    std::copy( arr.begin(), arr.end(), arrCopy.begin() );

    return fromString( arrCopy, base );
}

// -------------------- Operator Overloads -------------------- //

G1Point G1Point::operator+( const G1Point& other ) const {
    return G1Point( value + other.value );
}

G1Point G1Point::operator-( const G1Point& other ) const {
    return G1Point( value - other.value );
}

G1Point G1Point::operator-() const {
    return G1Point( -value );
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

#endif // LIBFF