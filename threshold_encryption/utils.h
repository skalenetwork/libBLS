#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <utility>

libff::alt_bn128_G1 MapToGroup(const std::string& message);

libff::alt_bn128_Fq CurveEquation(const libff::alt_bn128_Fq& field_elem);

bool IsQuadraticResidue(const libff::alt_bn128_Fq& field_elem);

libff::alt_bn128_Fq SquareRoot(const libff::alt_bn128_Fq& field_elem);