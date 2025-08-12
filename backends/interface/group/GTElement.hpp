#pragma once

#include "backends/algebra_types.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

namespace libBLS {
namespace algebra {

class GTElement {
public:
    GTBackendType value;
    GTElement( const GTBackendType& v ) : value( v ) {}
    GTElement();

    // -------------------- Operator Overloads -------------------- //

    GTElement operator*( const GTElement& other ) const;
    GTElement inverse() const;
    bool operator==( const GTElement& other ) const;
    bool operator!=( const GTElement& other ) const;
};

}  // namespace algebra
}  // namespace libBLS
