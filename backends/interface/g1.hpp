#pragma once

#include "fq.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

namespace libBLS {
namespace algebra {

class G1Point {

public:

#ifdef MCL
#else
    libff::alt_bn128_G1 value;

    G1Point(const libff::alt_bn128_G1& v) : value(v) {}
#endif

    G1Point();
    G1Point(const FqElement& x, const FqElement& y);

    void to_affine_coordinates();
    bool is_zero() const;
    bool is_well_formed() const;
    bool is_in_group() const;
    FqElement getX() const;
    FqElement getY() const;

    // --------------------- Static Methods -------------------- //

    static G1Point random();
    static G1Point zero();
    static G1Point one();

    // -------------------- Operator Overloads -------------------- //

    G1Point operator+(const G1Point& other) const;
    G1Point operator-(const G1Point& other) const;
    bool operator==(const G1Point& other) const;
    bool operator!=(const G1Point& other) const;
};

inline G1Point operator*(const FrScalar& scalar, const G1Point& point);

} // namespace algebra
} // namespace libBLS
