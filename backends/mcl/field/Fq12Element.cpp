
#ifdef MCL

#include "backends/interface/field/Fq12Element.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

// -------------------- Template Specializations -------------------- //
// Should be placed at start of file - must be defined before any
// code that uses them

template <>
Fq12Element Field< Fq12BackendType, Fq12Element >::zero() {
    Fq12BackendType zero;
    zero.clear();
    return Fq12Element( zero );
}

template <>
Fq12Element Field< Fq12BackendType, Fq12Element >::one() {
    assert( false ); // TODO: implement isOne for Fq12
    Fq12BackendType one;
    return Fq12Element( one );
}

template <>
bool Field< Fq12BackendType, Fq12Element >::isZero() const {
    return value.isZero();
}

template <>
bool Field< Fq12BackendType, Fq12Element >::isOne() const {
    assert( false ); // TODO: implement isOne for Fq12
    Fq12BackendType one;
    return value == one;
}

// -------------------- Constructors -------------------- //

Fq12Element::Fq12Element() {
    Fq12BackendType zero;
    zero.clear();
    value = zero;
}


Fq12Element& Fq12Element::operator*=( const Fq12Element& other ) {
    value *= other.value;
    return *this;
}


}  // namespace libBLS::algebra

#endif  // MCL