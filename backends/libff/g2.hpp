#pragma once

#include "fr.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libff_backend {

class G2Point {

public:
    libff::alt_bn128_G2 value;

    G2Point() {
        value = libff::alt_bn128_G2::zero();
    }

    G2Point(const libff::alt_bn128_G2& v) : value(v) {}

    void to_affine_coordinates() {
        value.to_affine_coordinates();
    }

    std::vector<std::string> toStringVector(int base);

    bool is_zero() const {
        return value.is_zero();
    }

    bool is_well_formed() const {
        return value.is_well_formed();
    }

    bool is_in_subgroup() const {
        return libff::alt_bn128_G2::order() * value == libff::alt_bn128_G2::zero();
    }

    // -------------------- Static Methods -------------------- //

    static G2Point random() {
        return G2Point(libff::alt_bn128_G2::random_element());
    }

    static G2Point zero() {
        return G2Point(libff::alt_bn128_G2::zero());
    }

    static G2Point one() {
        return G2Point(libff::alt_bn128_G2::one());
    }

    // -------------------- Operator Overloads -------------------- //

    G2Point operator+(const G2Point& other) const {
        return G2Point(value + other.value);
    }

    G2Point operator-(const G2Point& other) const {
        return G2Point(value - other.value);
    }

    bool operator==(const G2Point& other) const {
        return value == other.value;
    }

    bool operator!=(const G2Point& other) const {
        return value != other.value;
    }

};


inline G2Point operator*(const FrScalar& scalar, const G2Point& point) {
    return scalar.value * point.value;
}

}
