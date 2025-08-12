#include "backends/interface/group/GTElement.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

GTElement::GTElement() : value( libff::alt_bn128_GT::one() ) {}

GTElement GTElement::operator*( const GTElement& other ) const {
    return GTElement( value * other.value );
}

GTElement GTElement::inverse() const {
    return GTElement( value.inverse() );
}

bool GTElement::operator==( const GTElement& other ) const {
    return value == other.value;
}

bool GTElement::operator!=( const GTElement& other ) const {
    return value != other.value;
}

}  // namespace algebra
}  // namespace libBLS
