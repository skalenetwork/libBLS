#ifdef MCL

#include "backends/interface/group/G2Point.hpp"
#include "../utils.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/field/Fq2Element.hpp"
#include "backends/interface/field/FrScalar.hpp"
#include <iostream>

namespace libBLS::algebra {

G2Point::G2Point() {
    value = G2BackendType();
    value.clear();
}

G2Point::G2Point( const Fq2Element& x, const Fq2Element& y, const Fq2Element& z ) {
    value.x.a = x.asBackendType().a;
    value.x.b = x.asBackendType().b;
    value.y.a = y.asBackendType().a;
    value.y.b = y.asBackendType().b;
    value.z.a = z.asBackendType().a;
    value.z.b = z.asBackendType().b;
}

template <>
const G2BackendType& Group< G2BackendType, G2Point, Fq2Element >::identityBackend() {
    static const G2BackendType identity = [] {
        G2BackendType t;
        t.clear();
        return t;
    }();
    return identity;
}

template <>
const G2BackendType& Group< G2BackendType, G2Point, Fq2Element >::generatorBackend() {
    static const G2BackendType one = [] {
        G2BackendType one;
        one.clear();
        one.x.a.setStr( std::string( AltBn128Contract::g2_x0_dec ), mcl::bn::IoDec );
        one.x.b.setStr( std::string( AltBn128Contract::g2_x1_dec ), mcl::bn::IoDec );
        one.y.a.setStr( std::string( AltBn128Contract::g2_y0_dec ), mcl::bn::IoDec );
        one.y.b.setStr( std::string( AltBn128Contract::g2_y1_dec ), mcl::bn::IoDec );
        one.z.clear();
        one.z.a = FqBackendType::one();  // z = 1 (affine)
        if ( !one.isValid() )
            throw std::runtime_error( "mcl: G2::one not on curve" );
        return one;
    }();
    return one;
}

template <>
bool Group< G2BackendType, G2Point, Fq2Element >::isIdentity() const {
    return value.isZero();
}

template <>
bool Group< G2BackendType, G2Point, Fq2Element >::isGenerator() const {
    return value == generatorBackend();
}

template <>
void Group< G2BackendType, G2Point, Fq2Element >::toAffineCoordinates() {
    value.normalize();
}

// ------------------- Getters ------------------- //

template <>
Fq2Element Group< G2BackendType, G2Point, Fq2Element >::getX() const {
    return Fq2Element( value.x );
}
template <>
Fq2Element Group< G2BackendType, G2Point, Fq2Element >::getY() const {
    return Fq2Element( value.y );
}
template <>
Fq2Element Group< G2BackendType, G2Point, Fq2Element >::getZ() const {
    return Fq2Element( value.z );
}

// ------------------- Setters ------------------- //

template <>
void Group< G2BackendType, G2Point, Fq2Element >::setX( const Fq2Element& x ) {
    value.x = x.asBackendType();
}

template <>
void Group< G2BackendType, G2Point, Fq2Element >::setY( const Fq2Element& y ) {
    value.y = y.asBackendType();
}

template <>
void Group< G2BackendType, G2Point, Fq2Element >::setZ( const Fq2Element& z ) {
    value.z = z.asBackendType();
}

FqElement G2Point::getXC0() const {
    return FqElement( value.x.a );
}
FqElement G2Point::getXC1() const {
    return FqElement( value.x.b );
}
FqElement G2Point::getYC0() const {
    return FqElement( value.y.a );
}
FqElement G2Point::getYC1() const {
    return FqElement( value.y.b );
}
FqElement G2Point::getZC0() const {
    return FqElement( value.z.a );
}
FqElement G2Point::getZC1() const {
    return FqElement( value.z.b );
}


void G2Point::setXC0( const FqElement& x ) {
    value.x.a = x.asBackendType();
}
void G2Point::setXC1( const FqElement& x ) {
    value.x.b = x.asBackendType();
}
void G2Point::setYC0( const FqElement& y ) {
    value.y.a = y.asBackendType();
}
void G2Point::setYC1( const FqElement& y ) {
    value.y.b = y.asBackendType();
}
void G2Point::setZC0( const FqElement& z ) {
    value.z.a = z.asBackendType();
}
void G2Point::setZC1( const FqElement& z ) {
    value.z.b = z.asBackendType();
}

// -------------------- Validation Methods -------------------- //

template <>
bool Group< G2BackendType, G2Point, Fq2Element >::isWellFormed() const {
    return value.isValid();
}

template <>
bool Group< G2BackendType, G2Point, Fq2Element >::isInGroup() const {
    return value.isValidOrder();
}

// -------------------- Static Methods -------------------- //

template <>
G2Point Group< G2BackendType, G2Point, Fq2Element >::random() {
    FrBackendType r;
    r.setByCSPRNG();
    const G2BackendType& G = generatorBackend();
    G2BackendType Q;
    mcl::G2::mul( Q, G, r );
    return Q;
}

G2Point G2Point::fromBytes( const std::array< uint8_t, G2Point::SIZE_BYTES >& bytes ) {
    constexpr size_t FQ_SIZE = FqElement::SIZE_BYTES;
    const uint8_t* p = bytes.data();

    // helper to read an Fp from BE bytes
    auto readFp = [&]( mcl::bn::Fp& out ) {
        out.setBigEndianMod( p, FQ_SIZE );
        p += FQ_SIZE;
    };

    // build point
    G2BackendType P;
    readFp( P.x.a );
    readFp( P.x.b );
    readFp( P.y.a );
    readFp( P.y.b );
    P.z.clear();
    P.z.a = 1;

    return G2Point( P );
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
    algebra::G2Point ret;
    ret.value.z.clear();
    ret.value.z.a = FqBackendType::one();

    try {
        if ( base == Base::HEXA ) {
            // HEXA: fixed-width 64-char substrings (256 chars total)
            const size_t elementStringSize = MAX_FIELD_ELEMENT_SIZE_BYTES * 2;

            if ( str.size() != STRING_HEXA_CHARS ) {
                throw ThresholdUtils::IncorrectInput( "Wrong string size to convert to G2" );
            }

            trySettingFieldWithString(
                ret.value.x.a, str.substr( 0 * elementStringSize, elementStringSize ), base );
            trySettingFieldWithString(
                ret.value.x.b, str.substr( 1 * elementStringSize, elementStringSize ), base );
            trySettingFieldWithString(
                ret.value.y.a, str.substr( 2 * elementStringSize, elementStringSize ), base );
            trySettingFieldWithString(
                ret.value.y.b, str.substr( 3 * elementStringSize, std::string::npos ), base );
        } else {
            // DEC: colon-delimited variable-length decimal strings
            std::vector< std::string > parts;
            size_t start = 0;
            size_t end = 0;
            while ( ( end = str.find( ':', start ) ) != std::string::npos ) {
                parts.push_back( str.substr( start, end - start ) );
                start = end + 1;
            }
            parts.push_back( str.substr( start ) );

            if ( parts.size() != G2_NUM_COMPONENTS_AFFINE ) {
                throw ThresholdUtils::IncorrectInput(
                    "Wrong number of colon-delimited components for G2Point DEC string" );
            }

            trySettingFieldWithString( ret.value.x.a, parts[0], base );
            trySettingFieldWithString( ret.value.x.b, parts[1], base );
            trySettingFieldWithString( ret.value.y.a, parts[2], base );
            trySettingFieldWithString( ret.value.y.b, parts[3], base );
        }
    } catch ( const std::exception& e ) {
        throw ThresholdUtils::IncorrectInput(
            std::string( "Failed to set G2Point components from string: " ) + e.what() );
    }

    return ret;
}

G2Point G2Point::fromString(
    const std::array< std::string, G2_NUM_COMPONENTS_AFFINE >& arr, Base base ) {
    algebra::G2Point ret;
    ret.value.z.clear();
    ret.value.z.a = FqBackendType::one();

    try {
        trySettingFieldWithString( ret.value.x.a, arr.at( 0 ), base );
        trySettingFieldWithString( ret.value.x.b, arr.at( 1 ), base );
        trySettingFieldWithString( ret.value.y.a, arr.at( 2 ), base );
        trySettingFieldWithString( ret.value.y.b, arr.at( 3 ), base );
        return ret;
    } catch ( const std::exception& e ) {
        throw ThresholdUtils::IncorrectInput(
            std::string( "Failed to set G2Point components from string: " ) + e.what() );
    }
}

G2Point G2Point::fromString( const std::vector< std::string >& arr, Base base ) {
    if ( arr.size() != G2_NUM_COMPONENTS_AFFINE ) {
        throw ThresholdUtils::IncorrectInput( "Wrong number of components in G2Point" );
    }
    std::array< std::string, G2_NUM_COMPONENTS_AFFINE > arrCopy;
    std::copy( arr.begin(), arr.end(), arrCopy.begin() );
    return fromString( arrCopy, base );
}

// -------------------- Operator Overloads -------------------- //

G2Point G2Point::operator+( const G2Point& other ) const {
    return G2Point( value + other.value );
}

G2Point G2Point::operator+=( const G2Point& other ) {
    value += other.value;
    return *this;
}

G2Point G2Point::operator-( const G2Point& other ) const {
    return G2Point( value - other.value );
}

G2Point G2Point::operator-() const {
    return G2Point( -value );
}

bool G2Point::operator==( const G2Point& other ) const {
    return value == other.value;
}

bool G2Point::operator!=( const G2Point& other ) const {
    return value != other.value;
}

G2Point operator*( const FrScalar& scalar, const G2Point& point ) {
    G2BackendType result;
    mcl::G2::mul( result, point.asBackendType(), scalar.asBackendType() );
    return G2Point( result );
}


// -------------------- Helper methods for PointSerializer -------------------- //

void G2Point::forEachAffineComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    auto affine = value;
    affine.normalize();

    fn( FqElement( affine.x.a ), 0 );
    fn( FqElement( affine.x.b ), 1 );

    // compatibility with point at infinity representation across all backends
    value.isZero() ? fn( FqElement( 1 ), 2 ) : fn( FqElement( affine.y.a ), 2 );

    fn( FqElement( affine.y.b ), 3 );
}

void G2Point::forEachProjectiveComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    fn( FqElement( value.x.a ), 0 );
    fn( FqElement( value.x.b ), 1 );
    fn( FqElement( value.y.a ), 2 );
    fn( FqElement( value.y.b ), 3 );
    fn( FqElement( value.z.a ), 4 );
    fn( FqElement( value.z.b ), 5 );
}

}  // namespace libBLS::algebra

#endif  // MCL
