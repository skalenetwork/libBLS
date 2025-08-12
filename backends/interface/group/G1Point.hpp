#pragma once

#include "PointSerializer.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/WrapperCore.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

namespace libBLS {
namespace algebra {

constexpr size_t G1_NUM_COMPONENTS_AFFINE = 2;
constexpr size_t G1_NUM_COMPONENTS_PROJECTIVE = 3;

class G1Point
    : public WrapperCore< G1BackendType, G1Point >,
      public PointSerializer< G1Point, G1_NUM_COMPONENTS_AFFINE, G1_NUM_COMPONENTS_PROJECTIVE > {
public:
#ifdef MCL
#else
    static constexpr size_t SIZE_BYTES = 64;
#endif

    G1Point();  // Default constructor
    G1Point( const FqElement& x, const FqElement& y );
    G1Point( const FqElement& x, const FqElement& y, const FqElement& z );
    G1Point( const G1BackendType& v ) : WrapperCore( v ) {}

    void toAffineCoordinates();
    bool isZero() const;
    bool isWellFormed() const;
    bool isInGroup() const;
    bool isValid() const;
    void validate() const;

    FqElement getX() const;
    FqElement getY() const;

    FqRefWrapper getXRef() {
        return FqRefWrapper( value.X );
    }
    FqRefWrapper getYRef() {
        return FqRefWrapper( value.Y );
    }
    FqRefWrapper getZRef() {
        return FqRefWrapper( value.Z );
    }

    // --------------------- Static Methods -------------------- //

    static G1Point random();

    static G1Point fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes );
    static G1Point fromBytes( const std::vector< uint8_t >& bytes );
    static G1Point fromString( const std::string& str, Base base );
    static G1Point fromHash( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr );
    static G1Point fromHash( const std::string& message );

    // -------------------- Operator Overloads -------------------- //

    G1Point operator+( const G1Point& other ) const;
    G1Point operator-( const G1Point& other ) const;
    bool operator==( const G1Point& other ) const;
    bool operator!=( const G1Point& other ) const;

    // -------------------- Helper methods for PointSerializer -------------------- //

    void forEachAffineComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

    void forEachProjectiveComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;
};

G1Point operator*( const FrScalar& scalar, const G1Point& point );

}  // namespace algebra
}  // namespace libBLS
