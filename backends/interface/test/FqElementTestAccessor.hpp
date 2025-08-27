#pragma once

#include <ctime>
#include <random>

#include "backends/interface/field/FqElement.hpp"

namespace libBLS::algebra {

class FqElementTestAccessor {
    static std::default_random_engine rand_gen;

public:
    // TODO - could change in-place using reference
    static FqBackendType spoil( FqBackendType& elem );
};
}  // namespace libBLS::algebra