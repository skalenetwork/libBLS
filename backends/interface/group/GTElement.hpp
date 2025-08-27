#pragma once

#include "PointSerializer.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/field/FqElement.hpp"
#include "backends/interface/WrapperCore.hpp"


namespace libBLS {
namespace algebra {

constexpr size_t GT_NUM_COMPONENTS_AFFINE = 2;
constexpr size_t GT_NUM_COMPONENTS_PROJECTIVE = 3;

class GTElement : 
    public WrapperCore< GTBackendType, GTElement >,
    public PointSerializer< GTElement, GT_NUM_COMPONENTS_AFFINE, GT_NUM_COMPONENTS_PROJECTIVE > {
public:
    GTElement() {}
    GTElement( const GTBackendType& v ) : WrapperCore( v ) {}

    // -------------------- Operator Overloads -------------------- //

    GTElement operator*( const GTElement& other ) const;
    GTElement inverse() const;
    bool operator==( const GTElement& other ) const;
    bool operator!=( const GTElement& other ) const;


    // -------------------- Helper methods for PointSerializer -------------------- //

    void forEachAffineComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

    void forEachProjectiveComponentImpl(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const;

};

}  // namespace algebra
}  // namespace libBLS
