#pragma once

#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "FqElement.hpp"
#include "backends/algebra_types.hpp"


namespace libBLS::algebra {

class Fq2Element : public Field< Fq2BackendType, Fq2Element > {
private:
public:
    Fq2Element();
    Fq2Element( const Fq2BackendType& a ) : Field( a ) {}
    Fq2Element( const FqElement& a, const FqElement& b );
    Fq2Element( const FqBackendType& a, const FqBackendType& b );
};

}  // namespace libBLS::algebra
