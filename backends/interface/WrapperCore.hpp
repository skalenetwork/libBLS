#pragma once

namespace libBLS::algebra {

/// @brief Base parent class for algebraic types.
/// Holds the backend type `value` field.
/// Also provides getters for the backend type (both by value and reference).
/// This is common logic for all algebraic types.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper >
class WrapperCore {
protected:
    BackendType value;

public:
    WrapperCore() {}
    WrapperCore( const BackendType& backendValue ) : value( backendValue ) {}

    // Conversion to BackendType
    BackendType asBackendType() const { return value; }

    BackendType& asBackendRef() { return value; }
};

}  // namespace libBLS::algebra