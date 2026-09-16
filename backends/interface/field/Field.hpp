#pragma once
#include "backends/algebra_types.hpp"
#include "tools/utils.h"

namespace libBLS::algebra {

/// @brief Base parent class for field types.
/// Declares both zero() and one() static methods.
/// Includes all common serialization / deserialization methods from/to mpz_class.
/// @tparam BackendType - concrete backend type to be held by the wrappers
/// @tparam Wrapper - Wrapper class - needed for the one() and zero() methods
template < typename BackendType, typename Wrapper >
class Field : public WrapperCore< BackendType > {
protected:
public:
    Field() : WrapperCore< BackendType >() {}
    Field( const BackendType& v ) : WrapperCore< BackendType >( v ) {}

    // Must be declared as static functions, not fields.
    // We need to have initialized the curve before calling them.
    // If they were static fields, they would be both initialized as 0,
    // since the curve was not initialized yet.
    static Wrapper one();
    static Wrapper zero();

    bool isOne() const;
    bool isZero() const;
};

}  // namespace libBLS::algebra