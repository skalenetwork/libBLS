#pragma once

#ifndef MCL
#error "MCL backend must be defined"
#endif

#include <mcl/bn.hpp>

namespace libBLS {
namespace algebra {

void initCurve();

// ------------------- Define Backend Types ------------------- //

typedef mcl::Fr FrBackendType;
typedef mcl::Fp FqBackendType;
typedef mcl::Fp2 Fq2BackendType;
typedef mcl::Fp12 Fq12BackendType;
typedef mcl::G2 G2BackendType;
typedef mcl::G1 G1BackendType;
typedef mcl::GT GTBackendType;

}  // namespace algebra
}  // namespace libBLS
