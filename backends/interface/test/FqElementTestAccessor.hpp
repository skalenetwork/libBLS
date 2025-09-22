#pragma once

#include <ctime>
#include <random>

#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

class FqElementTestAccessor {
    static std::default_random_engine rand_gen;

public:
    static FqElement spoil( const FqElement& elem );
};
}  // namespace libBLS::algebra