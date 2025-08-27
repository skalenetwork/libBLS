#pragma once

#include <tools/utils.h>

namespace libBLS::algebra {

/// @brief Base parent class for Group types.
/// Declares both zero() and one() static methods.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper, typename BackendRefWrapper >
class Group : public WrapperCore< BackendType, Wrapper > {
protected:
    static const BackendType& generatorBackend();
    static const BackendType& identityBackend();

public:

    Group() : WrapperCore< BackendType, Wrapper >() {}
    Group( const BackendType& v) : WrapperCore< BackendType, Wrapper >( v ) {}

    void toAffineCoordinates();

    // ------------------- Getters ------------------- //

    BackendRefWrapper getXRef();
    BackendRefWrapper getYRef();
    BackendRefWrapper getZRef();

    // -------------------- Validation Methods -------------------- //

    bool isGenerator() const;
    bool isIdentity() const;
    bool isWellFormed() const;
    bool isInGroup() const;

    bool isValid() const {
        return !isIdentity() && isWellFormed() && isInGroup();
    }

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
        static const Wrapper one = Wrapper(generatorBackend());
        return one;
    }

    static Wrapper identity() {
        static const Wrapper zero = Wrapper(identityBackend());
        return zero;
    }

    static Wrapper random();

    // static Wrapper fromBytes( const std::array< uint8_t, Wrapper::SIZE_BYTES >& bytes );
    // static Wrapper fromBytes( const std::vector< uint8_t >& bytes );

    // static Wrapper fromString( const std::string& str, Base base );
    // static Wrapper fromString(
    //     const std::array< std::string, Wrapper::NUM_COMPONENTS_AFFINE >& arr, Base base );
    // // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the
    // // size
    // static Wrapper fromString( const std::vector< std::string >& arr, Base base );

};

}  // namespace libBLS::algebra