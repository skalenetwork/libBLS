#pragma once

#include <gmpxx.h>
#include <ctime>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
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