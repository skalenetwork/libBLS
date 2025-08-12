#include "../interface/init.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>

namespace libBLS {
namespace algebra {

void initCurve() {
    libff::alt_bn128_pp::init_public_params();
    libff::inhibit_profiling_info = true;
}

}  // namespace algebra
}  // namespace libBLS
