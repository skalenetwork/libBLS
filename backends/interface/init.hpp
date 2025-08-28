#pragma once

#if defined( MCL ) && defined( LIBFF )
#error "Both MCL and LIBFF defined"
#endif
#if !defined( MCL ) && !defined( LIBFF )
#error "Neither MCL nor LIBFF defined"
#endif


#ifdef MCL
#include <mcl/bn.hpp>
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#endif

namespace libBLS {
namespace algebra {

void initCurve();

// ------------------- Define Backend Types ------------------- //

#ifdef MCL
typedef mcl::Fr FrBackendType;
typedef mcl::Fp FqBackendType;
typedef mcl::Fp2 Fq2BackendType;
typedef mcl::G2 G2BackendType;
typedef mcl::G1 G1BackendType;
typedef mcl::GT GTBackendType;
#else
typedef libff::alt_bn128_Fr FrBackendType;
typedef libff::alt_bn128_Fq FqBackendType;
typedef libff::alt_bn128_Fq2 Fq2BackendType;
typedef libff::alt_bn128_G2 G2BackendType;
typedef libff::alt_bn128_G1 G1BackendType;
typedef libff::alt_bn128_GT GTBackendType;
#endif

}  // namespace algebra
}  // namespace libBLS
