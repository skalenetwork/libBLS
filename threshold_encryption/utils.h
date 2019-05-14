#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <utility>

class G2;

libff::alt_bn128_Fq CurveEquation(const libff::alt_bn128_Fq& field_elem);

bool IsQuadraticResidue(const libff::alt_bn128_Fq& field_elem);

libff::alt_bn128_Fq SquareRoot(const libff::alt_bn128_Fq& field_elem);

libff::alt_bn128_Fq12 ComputeLine(const libff::alt_bn128_Fq12 R, const libff::alt_bn128_Fq12 P,
                                                                    const libff::alt_bn128_Fq12 Q);

libff::alt_bn128_Fq12 ComputeTangentLine(const libff::alt_bn128_G2& P,
                                          const libff::alt_bn128_G2& Q);

libff::alt_bn128_Fq12 ComputeVerticalLine(const libff::alt_bn128_G2& P,
                                          const libff::alt_bn128_G2& Q);

libff::alt_bn128_Fq12 MillerLoop(const libff::alt_bn128_G2& P, const libff::alt_bn128_G2& Q);

libff::alt_bn128_GT WeilPairing(const libff::alt_bn128_G2& P, const libff::alt_bn128_G2& Q);