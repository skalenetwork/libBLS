#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#include <ctime>
#include <random>
#include <gmpxx.h>

#include "../fq.hpp"

namespace libBLS::algebra {

class FqElementTestAccessor {
    static std::default_random_engine rand_gen;
public:
    // TODO - could change in-place using reference
    static FqBackendType spoil( FqBackendType& elem );
};
} // namespace libBLS::algebra