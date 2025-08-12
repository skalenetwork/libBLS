#pragma once

#include "PointSerializer.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/WrapperCore.hpp"
#include "backends/interface/field/Fq2Element.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

namespace libBLS::algebra {

constexpr size_t G2_NUM_COMPONENTS_AFFINE = 4;
constexpr size_t G2_NUM_COMPONENTS_PROJECTIVE = 6;

class G2Point
    : public WrapperCore< G2BackendType, G2Point >,
      public PointSerializer< G2Point, G2_NUM_COMPONENTS_AFFINE, G2_NUM_COMPONENTS_PROJECTIVE > {
public:
#ifdef MCL
#else
    static constexpr std::size_t SIZE_BYTES = 128;
#endif

    G2Point();
    G2Point( const G2BackendType v ) : WrapperCore( v ) {}
    G2Point( const Fq2Element& x, const Fq2Element& y, const Fq2Element& z );

    void toAffineCoordinates();

    // ------------------- Getters ------------------- //

    Fq2RefWrapper getXRef() {
        return Fq2RefWrapper( value.X );
    }
    Fq2RefWrapper getYRef() {
        return Fq2RefWrapper( value.Y );
    }
    Fq2RefWrapper getZRef() {
        return Fq2RefWrapper( value.Z );
    }

    // -------------------- Validation Methods -------------------- //

    bool isZero() const;
    bool isWellFormed() const;
    bool isInGroup() const;
    bool isValid() const;
    void validate() const;

    // -------------------- Static Methods -------------------- //

    static G2Point random();

    static G2Point fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes );
    static G2Point fromBytes( const std::vector< uint8_t >& bytes );

    static G2Point fromString( const std::string& str, Base base );
    static G2Point fromString(
        const std::array< std::string, G2_NUM_COMPONENTS_AFFINE >& arr, Base base );
    // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the
    // size
    static G2Point fromString( const std::vector< std::string >& arr, Base base );

    // -------------------- Operator Overloads -------------------- //

    G2Point operator+( const G2Point& other ) const;
    G2Point operator-( const G2Point& other ) const;
    bool operator==( const G2Point& other ) const;
    bool operator!=( const G2Point& other ) const;

    // -------------------- Helper methods for PointSerializer -------------------- //

    void forEachAffineComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

    void forEachProjectiveComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;
};

G2Point operator*( const FrScalar& scalar, const G2Point& point );

}  // namespace libBLS::algebra
