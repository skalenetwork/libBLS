#ifdef LIBFF

#include "backends/interface/group/GTElement.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

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


void GTElement::forEachAffineComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    fn(FqElement(value.c0.c0.c0),  0);
    fn(FqElement(value.c0.c0.c1),  1);
    fn(FqElement(value.c0.c1.c0),  2);
    fn(FqElement(value.c0.c1.c1),  3);
    fn(FqElement(value.c0.c2.c0),  4);
    fn(FqElement(value.c0.c2.c1),  5);

    fn(FqElement(value.c1.c0.c0),  6);
    fn(FqElement(value.c1.c0.c1),  7);
    fn(FqElement(value.c1.c1.c0),  8);
    fn(FqElement(value.c1.c1.c1),  9);
    fn(FqElement(value.c1.c2.c0), 10);
    fn(FqElement(value.c1.c2.c1), 11);
}

void GTElement::forEachProjectiveComponentImpl(
    const std::function< void( const FqElement&, size_t i ) >& fn ) const {
    fn( FqElement( value.c0.c0.c0 ), 0 );
    fn( FqElement( value.c0.c0.c1 ), 1 );
    fn( FqElement( value.c0.c1.c0 ), 2 );
    fn( FqElement( value.c0.c1.c1 ), 3 );
    fn( FqElement( value.c1.c0.c0 ), 4 );
    fn( FqElement( value.c1.c0.c1 ), 5 );
    fn( FqElement( value.c1.c1.c0 ), 6 );
    fn( FqElement( value.c1.c1.c1 ), 7 );
}


}  // namespace algebra
}  // namespace libBLS

#endif // LIBFF