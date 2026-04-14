#pragma once

#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "Fq12Element.hpp"
#include "backends/algebra_types.hpp"


namespace libBLS::algebra {

class Fq12Element : public Field< Fq12BackendType, Fq12Element > {
private:
public:
    Fq12Element();
    Fq12Element( const Fq12BackendType& a ) : Field( a ) {}

    Fq12Element& operator*=( const Fq12Element& other );
};

}  // namespace libBLS::algebra