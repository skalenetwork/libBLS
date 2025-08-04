#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>

namespace libff_backend {

class FrScalar {

public:
    libff::alt_bn128_Fr value;

    FrScalar() {
        value = libff::alt_bn128_Fr::zero();
    }

    FrScalar(const libff::alt_bn128_Fr& v) : value(v) {}

    FrScalar inverse() const {
        return FrScalar(value.inverse());
    }

    bool is_zero() const {
        return value.is_zero();
    }
    // -------------------- Static Methods -------------------- // 

    static FrScalar random() {
        return FrScalar(libff::alt_bn128_Fr::random_element());
    }
    static FrScalar zero() {
        return FrScalar(libff::alt_bn128_Fr::zero());
    }
    static FrScalar one() {
        return FrScalar(libff::alt_bn128_Fr::one());
    }

    // -------------------- Operator Overloads -------------------- //

    FrScalar operator+(const FrScalar& other) const {
        return FrScalar(value + other.value);
    }

    FrScalar operator-(const FrScalar& other) const {
        return FrScalar(value - other.value);
    }

    FrScalar operator*(const FrScalar& other) const {
        return FrScalar(value * other.value);
    }

    FrScalar operator+=(const FrScalar& other) {
        value += other.value;
        return *this;
    }

    FrScalar operator*=(const FrScalar& other) {
        value *= other.value;
        return *this;
    }

    bool operator==(const FrScalar& other) const {
        return value == other.value;
    }

    bool operator!=(const FrScalar& other) const {
        return value != other.value;
    }
};

}
