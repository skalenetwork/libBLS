#ifdef MCL

#include "backends/interface/group/G1Point.hpp"
#include "../utils.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"
#include <tools/utils.h>
#include <array>

namespace libBLS {
namespace algebra {

template <>
const G1BackendType& Group< G1BackendType, G1Point, FqElement >::identityBackend() {
    static const G1BackendType identity = [] {
        G1BackendType identity;
        identity.clear();
        return identity;
    }();
    return identity;
}

template <>
const G1BackendType& Group< G1BackendType, G1Point, FqElement >::generatorBackend() {
    static const G1BackendType generator = [] {
        G1BackendType generator;
        generator.clear();
        generator.x.setStr( std::string( AltBn128Contract::g1_x_dec ), mcl::bn::IoDec );
        generator.y.setStr( std::string( AltBn128Contract::g1_y_dec ), mcl::bn::IoDec );
        generator.z = 1;  // affine
        if ( !generator.isValid() )
            throw std::runtime_error( "mcl: G1::generator not on curve" );
        return generator;
    }();
    return generator;
}

G1Point::G1Point() {
    value = identityBackend();
}

G1Point::G1Point( const FqElement& x, const FqElement& y ) {
    value.x = x.asBackendType();
    value.y = y.asBackendType();
    value.z = FqBackendType::one();
}

G1Point::G1Point( const FqElement& x, const FqElement& y, const FqElement& z ) {
    value.x = x.asBackendType();
    value.y = y.asBackendType();
    value.z = z.asBackendType();
}

template <>
bool Group< G1BackendType, G1Point, FqElement >::isIdentity() const {
    return value.isZero();
}

template <>
bool Group< G1BackendType, G1Point, FqElement >::isGenerator() const {
    return value == generatorBackend();
}

template <>
void Group< G1BackendType, G1Point, FqElement >::toAffineCoordinates() {
    value.normalize();
}

template <>
bool Group< G1BackendType, G1Point, FqElement >::isWellFormed() const {
    return value.isValid();
}

template <>
bool Group< G1BackendType, G1Point, FqElement >::isInGroup() const {
    return value.isValid() && value.isValidOrder();
}

// ------------------- Getters ------------------- //

template <>
FqElement Group< G1BackendType, G1Point, FqElement >::getX() const {
    return FqElement( value.x );
}
template <>
FqElement Group< G1BackendType, G1Point, FqElement >::getY() const {
    return FqElement( value.y );
}
template <>
FqElement Group< G1BackendType, G1Point, FqElement >::getZ() const {
    return FqElement( value.z );
}

// ------------------- Setters ------------------- //

template <>
void Group< G1BackendType, G1Point, FqElement >::setX( const FqElement& x ) {
    value.x = x.asBackendType();
}

template <>
void Group< G1BackendType, G1Point, FqElement >::setY( const FqElement& y ) {
    value.y = y.asBackendType();
}

template <>
void Group< G1BackendType, G1Point, FqElement >::setZ( const FqElement& z ) {
    value.z = z.asBackendType();
}

// --------------------- Static Methods -------------------- //


template <>
G1Point Group< G1BackendType, G1Point, FqElement >::random() {
    return randomGroupPoint< G1Point, GroupPoint::G1 >();
}


G1Point G1Point::fromBytes( const std::array< uint8_t, G1Point::SIZE_BYTES >& bytes ) {
    constexpr size_t FQ_SIZE = FqElement::SIZE_BYTES;
    const uint8_t* p = bytes.data();

    // helper to read an Fp from Big endian bytes
    auto readFp = [&]( mcl::bn::Fp& out ) {
        out.setBigEndianMod( p, FQ_SIZE );
        p += FQ_SIZE;
    };

    // build point
    G1BackendType P;
    readFp( P.x );
    readFp( P.y );
    P.z = FqBackendType::one();
    return G1Point( P );
}

G1Point G1Point::fromString( const std::string& str, Base base ) {
    if ( base != Base::HEXA ) {
        throw ThresholdUtils::IncorrectInput(
            "G1Point is currently only supported to be built from hexadecimal base string" );
    }

    const size_t stringSize = 128;
    const size_t elementStringSize = 64;

    if ( str.size() != stringSize ) {
        throw ThresholdUtils::IncorrectInput( "Wrong string size to convert to G1" );
    }

    algebra::G1Point ret;

    ret.value.z = FqBackendType::one();

    try {
        trySettingFieldWithString(
            ret.value.x, str.substr( 0 * elementStringSize, elementStringSize ), base );
        trySettingFieldWithString(
            ret.value.y, str.substr( 1 * elementStringSize, elementStringSize ), base );
    } catch ( const std::exception& e ) {
        throw ThresholdUtils::IncorrectInput(
            std::string( "Failed to set G2Point components from string: " ) + e.what() );
    }

    return ret;
}

G1Point G1Point::fromString(
    const std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE >& arr, Base base ) {
    algebra::G1Point ret;
    ret.value.z = FqBackendType::one();

    try {
        trySettingFieldWithString( ret.value.x, arr.at( 0 ), base );
        trySettingFieldWithString( ret.value.y, arr.at( 1 ), base );
        return ret;
    } catch ( const std::exception& e ) {
        throw ThresholdUtils::IncorrectInput(
            std::string( "Failed to set G1Point components from string: " ) + e.what() );
    }
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
    G1BackendType result;
    mcl::G1::mul( result, point.asBackendType(), scalar.asBackendType() );
    return G1Point( result );
}

// -------------------- Helper methods for PointSerializer -------------------- //

void G1Point::forEachAffineComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto affine = value;
    affine.normalize();

    fn( FqElement( affine.x ), 0 );

    // compatibility with point at infinity representation across all backends
    value.isZero() ? fn( FqElement( 1 ), 1 ) : fn( FqElement( affine.y ), 1 );
}

void G1Point::forEachProjectiveComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    fn( FqElement( value.x ), 0 );
    fn( FqElement( value.y ), 1 );
    fn( FqElement( value.z ), 2 );
}

}  // namespace algebra
}  // namespace libBLS

#endif  // MCL