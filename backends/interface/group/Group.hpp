#pragma once

#include "backends/interface/WrapperCore.hpp"
#include <tools/utils.h>

namespace libBLS::algebra {

/// @brief Base parent class for Group types.
/// Declares both zero() and one() static methods.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper, typename CoordsType >
class Group : public WrapperCore< BackendType > {
protected:
    static const BackendType& generatorBackend();
    static const BackendType& identityBackend();

public:
    Group() : WrapperCore< BackendType >() {}
    Group( const BackendType& v ) : WrapperCore< BackendType >( v ) {}

    void toAffineCoordinates();

    // ------------------- Getters ------------------- //

    void setX( const CoordsType& x );
    void setY( const CoordsType& y );
    void setZ( const CoordsType& z );

    // -------------------- Setters ------------------- //

    CoordsType getX() const;
    CoordsType getY() const;
    CoordsType getZ() const;

    // -------------------- Validation Methods -------------------- //

    bool isGenerator() const;
    bool isIdentity() const;
    bool isWellFormed() const;
    bool isInGroup() const;

    bool isValid() const { return !isIdentity() && isWellFormed() && isInGroup(); }

    void validate() const {
        if ( isIdentity() ) {
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

    // Must be declared as static functions, not fields.
    // We need to have initialized the curve before calling them.
    // If they were static fields, they would be both initialized as 0,
    // since the curve was not initialized yet.
    static Wrapper generator() {
        static const Wrapper one = Wrapper( generatorBackend() );
        return one;
    }

    static Wrapper identity() {
        static const Wrapper zero = Wrapper( identityBackend() );
        return zero;
    }

    static Wrapper random();
};

}  // namespace libBLS::algebra