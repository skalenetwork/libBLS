#pragma once

#include "PointSerializer.hpp"
#include "Group.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/WrapperCore.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/field/FrScalar.hpp"



namespace libBLS {
namespace algebra {


// avoid circular dependency with functions.hpp
class G1Point;
G1Point hashToG1( const std::array< uint8_t, 32 >& hash_byte_arr );
G1Point hashToG1( const std::string& message );


constexpr size_t G1_NUM_COMPONENTS_AFFINE = 2;
constexpr size_t G1_NUM_COMPONENTS_PROJECTIVE = 3;

class G1Point :
      public Group< G1BackendType, G1Point, FqRefWrapper >,
      public PointSerializer< G1Point, G1_NUM_COMPONENTS_AFFINE, G1_NUM_COMPONENTS_PROJECTIVE > {
public:
    static constexpr size_t SIZE_BYTES = 64;
    static constexpr size_t NUM_COMPONENTS_AFFINE = G1_NUM_COMPONENTS_AFFINE;

    G1Point();  // Default constructor
    G1Point( const FqElement& x, const FqElement& y );
    G1Point( const FqElement& x, const FqElement& y, const FqElement& z );
    G1Point( const G1BackendType& v ) : Group( v ) {}

    FqElement getX() const;
    FqElement getY() const;

    // -------------------- Operator Overloads -------------------- //

    G1Point operator+( const G1Point& other ) const;
    G1Point operator-( const G1Point& other ) const;
    G1Point operator-() const;
    bool operator==( const G1Point& other ) const;
    bool operator!=( const G1Point& other ) const;

    // -------------------- Helper methods for PointSerializer -------------------- //

    static G1Point fromBytes( const std::array< uint8_t, G1Point::SIZE_BYTES >& bytes );


    static G1Point fromHash( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr ) {
        return hashToG1( hash_byte_arr );
    }

    static G1Point fromHash( const std::string& message ) {
        return hashToG1( message );
    }

    static G1Point fromBytes( const std::vector< uint8_t >& bytes ) {
    if ( bytes.size() != G1Point::SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Wrong byte vector size to convert to G1Point" );
    }

    std::array< uint8_t, G1Point::SIZE_BYTES > arr;
    std::copy( bytes.begin(), bytes.end(), arr.begin() );

    return fromBytes( arr );    
}

    static G1Point fromString( const std::string& str, Base base );
    static G1Point fromString(
        const std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE >& arr, Base base );
    // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the
    // size
    static G1Point fromString( const std::vector< std::string >& arr, Base base );


    void forEachAffineComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

    void forEachProjectiveComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;
};

G1Point operator*( const FrScalar& scalar, const G1Point& point );

}  // namespace algebra
}  // namespace libBLS
