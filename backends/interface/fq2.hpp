#pragma once

#include "fq.hpp"
#include "../algebra_types.hpp"


namespace libBLS::algebra {

class Fq2Element {
public:
    FqElement c0;
    FqElement c1;

    Fq2Element(const FqElement& a, const FqElement& b) : c0(a), c1(b) {}
};

class Fq2RefWrapper {
    Fq2BackendType ref_;
public:
    explicit Fq2RefWrapper(Fq2BackendType& ref) : ref_(ref) {}

    FqRefWrapper getC0Ref();
    FqRefWrapper getC1Ref();

    Fq2BackendType& asBackendRef() { return ref_; }
};

}
