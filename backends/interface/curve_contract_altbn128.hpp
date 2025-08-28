#pragma once
#include <string_view>

namespace libBLS::algebra {

class FqElement;

/**
 * Defines the elliptic curve contract for alt_bn128.
 * This contract specifies the curve parameters, including the coefficients,
 * the generator points, and the field characteristics.
 * It is used to ensure compatibility with the alt_bn128 curve implementation
 * across different elliptic curve libraries.
 * @note The values used here are based on the libff library's alt_bn128 implementation.
 *        Any other backend library used, other than libff, must adhere to these values.
 */
struct AltBn128Contract {
    // Base curve: y^2 = x^3 + 3 over Fp
    static constexpr std::string_view coeff_a_dec = "0";
    static constexpr std::string_view coeff_b_dec = "3";

    // Moduli (decimal strings, from libff alt_bn128_init.cpp)
    static constexpr std::string_view p_dec =
        "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    static constexpr std::string_view r_dec =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    // Euler exponent (p-1)/2
    static constexpr std::string_view fq_euler_dec =
        "10944121435919637611123202872628637544348155578648911831344518947322613104291";

    // Fp2 model (u^2 = -1); we record this for documentation/interop
    // limb order is (a, b) for a + b*u

    // G1 generator (affine) used by alt_bn128
    static constexpr std::string_view g1_x_dec = "1";
    static constexpr std::string_view g1_y_dec = "2";

    // G2 generator (affine) used by alt_bn128 (decimal limbs: X=(x0+x1*u), Y=(y0+y1*u))
    static constexpr std::string_view g2_x0_dec =
        "10857046999023057135944570762232829481370756359578518086990519993285655852781";
    static constexpr std::string_view g2_x1_dec =
        "11559732032986387107991004021392285783925812861821192530917403151452391805634";
    static constexpr std::string_view g2_y0_dec =
        "8495653923123431417604973247489272438418190587263600148770280649306958101930";
    static constexpr std::string_view g2_y1_dec =
        "4082367875863433681332203403145435568316851327593401208105741076214120093531";

    static const FqElement& coeffB();
};


}  // namespace libBLS::algebra