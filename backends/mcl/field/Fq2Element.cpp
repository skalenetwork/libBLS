
#ifdef MCL

#include "backends/interface/field/Fq2Element.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

// -------------------- Template Specializations -------------------- //
// Should be placed at start of file - must be defined before any
// code that uses them

template <>
Fq2Element Field< Fq2BackendType, Fq2Element >::zero() {
    Fq2BackendType zero;
    zero.clear();
    return Fq2Element( zero );
}

template <>
Fq2Element Field< Fq2BackendType, Fq2Element >::one() {
    Fq2BackendType one;
    one.clear();
    one.a = FqBackendType::one();
    return Fq2Element( one );
}

template <>
bool Field< Fq2BackendType, Fq2Element >::isZero() const {
    return value.isZero();
}

template <>
bool Field< Fq2BackendType, Fq2Element >::isOne() const {
    Fq2BackendType one;
    one.clear();
    one.a = FqBackendType::one();
    return value == one;
}

// -------------------- Constructors -------------------- //

Fq2Element::Fq2Element() {
    Fq2BackendType zero;
    zero.clear();
    value = zero;
}

Fq2Element::Fq2Element( const FqElement& a, const FqElement& b ) {
    value = Fq2BackendType( a.value, b.value );
}

Fq2Element::Fq2Element( const FqBackendType& a, const FqBackendType& b ) {
    value = Fq2BackendType( a, b );
}

FqRefWrapper Fq2RefWrapper::getC0Ref() {
    return FqRefWrapper( ref_.a );
}
FqRefWrapper Fq2RefWrapper::getC1Ref() {
    return FqRefWrapper( ref_.b );
}


}  // namespace libBLS::algebra

#endif  // MCL