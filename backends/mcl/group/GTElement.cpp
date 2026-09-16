#ifdef MCL

#include "backends/interface/group/GTElement.hpp"

namespace libBLS {
namespace algebra {

GTElement GTElement::operator*( const GTElement& other ) const {
    return GTElement( value * other.value );
}

GTElement GTElement::inverse() const {
    GTBackendType inv;
    mcl::GT::inv( inv, value );
    return GTElement( inv );
}

bool GTElement::operator==( const GTElement& other ) const {
    return value == other.value;
}

bool GTElement::operator!=( const GTElement& other ) const {
    return value != other.value;
}

}  // namespace algebra
}  // namespace libBLS

#endif  // MCL