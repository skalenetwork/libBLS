#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libff_backend {

class G1Point {

public:
    libff::alt_bn128_G1 value;

    G1Point() {
        value = libff::alt_bn128_G1::zero();
    }

    G1Point(const libff::alt_bn128_G1& v) : value(v) {}

    void to_affine_coordinates() {
        value.to_affine_coordinates();
    }

    bool is_zero() const {
        return value.is_zero();
    }

    bool is_well_formed() const {
        return value.is_well_formed();
    }

    bool is_in_group() const {
        return libff::alt_bn128_modulus_r * value == libff::alt_bn128_G1::zero();
    }

    // --------------------- Static Methods -------------------- //

    static G1Point random() {
        return G1Point(libff::alt_bn128_G1::random_element());
    }

    static G1Point zero() {
        return G1Point(libff::alt_bn128_G1::zero());
    }

    static G1Point one() {
        return G1Point(libff::alt_bn128_G1::one());
    }

    // -------------------- Operator Overloads -------------------- //

    G1Point operator+(const G1Point& other) const {
        return G1Point(value + other.value);
    }

    G1Point operator-(const G1Point& other) const {
        return G1Point(value - other.value);
    }

    bool operator==(const G1Point& other) const {
        return value == other.value;
    }

    bool operator!=(const G1Point& other) const {
        return value != other.value;
    }
};

inline G1Point operator*(const FrScalar& scalar, const G1Point& point) {
    return G1Point(scalar.value * point.value);
}

}
