#include "backends/interface/field/Fq2Element.hpp"
#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

Fq2Element::Fq2Element( const FqElement& a, const FqElement& b ) {
    value = libff::alt_bn128_Fq2( a.value, b.value );
}

Fq2Element::Fq2Element( const FqBackendType& a, const FqBackendType& b ) {
    value = libff::alt_bn128_Fq2( a, b );
}

FqRefWrapper Fq2RefWrapper::getC0Ref() {
    return FqRefWrapper( ref_.c0 );
}
FqRefWrapper Fq2RefWrapper::getC1Ref() {
    return FqRefWrapper( ref_.c1 );
}

template <>
Fq2Element WrapperCore< Fq2BackendType, Fq2Element >::zero() {
    return Fq2Element( libff::alt_bn128_Fq2::zero() );
}

template <>
Fq2Element WrapperCore< Fq2BackendType, Fq2Element >::one() {
    return Fq2Element( libff::alt_bn128_Fq2::one() );
}

}  // namespace libBLS::algebra