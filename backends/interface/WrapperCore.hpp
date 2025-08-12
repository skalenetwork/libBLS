#pragma once

namespace libBLS::algebra {

/// @brief Base parent class for algebraic types.
/// Declares both zero() and one() static methods, as well as the backend type `value` field.
/// Also provides getters for the backend type (both by value and reference).
/// This is common logic for all algebraic types.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper >
class WrapperCore {
public:
    BackendType value;

    WrapperCore() {}
    WrapperCore( const BackendType& backendValue ) : value( backendValue ) {}

    // Conversion to BackendType
    BackendType asBackendType() const { return value; }

    BackendType& asBackendRef() { return value; }

    // Must be declared as static functions, not fields.
    // We need to have initialized the curve before calling them.
    // If they were static fields, they would be both initialized as 0,
    // since the curve was not initialized yet.
    static Wrapper one();
    static Wrapper zero();
};

}  // namespace libBLS::algebra