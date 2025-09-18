#pragma once

#include "Group.hpp"
#include "PointSerializer.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/WrapperCore.hpp"
#include "backends/interface/field/Fq2Element.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"

namespace libBLS::algebra {

constexpr size_t G2_NUM_COMPONENTS_AFFINE = 4;
constexpr size_t G2_NUM_COMPONENTS_PROJECTIVE = 6;

class G2Point
    : public Group< G2BackendType, G2Point, Fq2RefWrapper >,
      public PointSerializer< G2Point, G2_NUM_COMPONENTS_AFFINE, G2_NUM_COMPONENTS_PROJECTIVE > {
public:
    static constexpr size_t SIZE_BYTES = 128;
    static constexpr size_t STRING_HEXA_CHARS = 2 * SIZE_BYTES;
    static constexpr size_t NUM_COMPONENTS_AFFINE = G2_NUM_COMPONENTS_AFFINE;

    G2Point();
    G2Point( const G2BackendType v ) : Group( v ) {}
    G2Point( const Fq2Element& x, const Fq2Element& y, const Fq2Element& z );

    // -------------------- Operator Overloads -------------------- //

    G2Point operator+( const G2Point& other ) const;
    G2Point operator+=( const G2Point& other );
    G2Point operator-( const G2Point& other ) const;
    G2Point operator-() const;
    bool operator==( const G2Point& other ) const;
    bool operator!=( const G2Point& other ) const;

    // -------------------- Helper methods for PointSerializer -------------------- //

    static G2Point fromBytes( const std::array< uint8_t, G2Point::SIZE_BYTES >& bytes );
    static G2Point fromBytes( const std::vector< uint8_t >& bytes );

    static G2Point fromString( const std::string& str, Base base );
    static G2Point fromString(
        const std::array< std::string, G2Point::NUM_COMPONENTS_AFFINE >& arr, Base base );
    // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the
    // size
    static G2Point fromString( const std::vector< std::string >& arr, Base base );

    void forEachAffineComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

    void forEachProjectiveComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;
};

inline std::ostream& operator<<( std::ostream& os, G2Point const& point ) {
    // Choose HEX or DEC encoding depending on your needs
    return os << point.toString( libBLS::Base::HEXA );
}

G2Point operator*( const FrScalar& scalar, const G2Point& point );

}  // namespace libBLS::algebra
