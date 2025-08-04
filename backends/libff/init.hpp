#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <profiling.hpp>

namespace libff_backend {

inline void init_curve() {
    libff::alt_bn128_pp::init_public_params();
    libff::inhibit_profiling_info = true;
}

}
