#ifdef LIBFF

#include "backends/interface/field/Fq2Element.hpp"
#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

template <>
Fq2Element Field< Fq2BackendType, Fq2Element >::zero() {
    return Fq2Element( Fq2BackendType::zero() );
}

template <>
Fq2Element Field< Fq2BackendType, Fq2Element >::one() {
    return Fq2Element( Fq2BackendType::one() );
}

template <>
bool Field< Fq2BackendType, Fq2Element >::isZero() const {
    return value.is_zero();
}

template <>
bool Field< Fq2BackendType, Fq2Element >::isOne() const {
    return value == Fq2BackendType::one();
}

Fq2Element::Fq2Element() {}

Fq2Element::Fq2Element( const FqElement& a, const FqElement& b ) {
    value = Fq2BackendType( a.value, b.value );
}

Fq2Element::Fq2Element( const FqBackendType& a, const FqBackendType& b ) {
    value = Fq2BackendType( a, b );
}

FqRefWrapper Fq2RefWrapper::getC0Ref() {
    return FqRefWrapper( ref_.c0 );
}
FqRefWrapper Fq2RefWrapper::getC1Ref() {
    return FqRefWrapper( ref_.c1 );
}

}  // namespace libBLS::algebra

#endif  // LIBFF