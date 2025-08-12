#pragma once

#include "../WrapperCore.hpp"
#include "FqElement.hpp"
#include "backends/algebra_types.hpp"


namespace libBLS::algebra {

class Fq2Element : public WrapperCore< Fq2BackendType, Fq2Element > {
private:
public:
    Fq2Element( const Fq2BackendType& a ) : WrapperCore( a ) {}
    Fq2Element( const FqElement& a, const FqElement& b );
    Fq2Element( const FqBackendType& a, const FqBackendType& b );
};

class Fq2RefWrapper {
    Fq2BackendType& ref_;

public:
    explicit Fq2RefWrapper( Fq2BackendType& ref ) : ref_( ref ) {}

    FqRefWrapper getC0Ref();
    FqRefWrapper getC1Ref();

    Fq2BackendType& asBackendRef() { return ref_; }
};

}  // namespace libBLS::algebra
