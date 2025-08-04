#pragma once

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>

namespace libff_backend {

class FqElement {

public:
    libff::alt_bn128_Fq value;

    FqElement() : value(libff::alt_bn128_Fq::zero()) {}

    FqElement(const libff::alt_bn128_Fq& val) : value(val) {}

    FqElement(uint64_t x) : value(libff::alt_bn128_Fq(x)) {}

    // -------------------- Operator Overloads -------------------- //

    FqElement operator+(const FqElement& other) const {
        return FqElement(value + other.value);
    }

    FqElement operator-(const FqElement& other) const {
        return FqElement(value - other.value);
    }

    FqElement operator*(const FqElement& other) const {
        return FqElement(value * other.value);
    }

    FqElement& operator+=(const FqElement& other) {
        value += other.value;
        return *this;
    }

    FqElement operator^(const unsigned long pow) {
        return FqElement(value ^ pow);
    }

    FqElement& operator*=(const FqElement& other) {
        value *= other.value;
        return *this;
    }

    bool operator==(const FqElement& other) const {
        return value == other.value;
    }

    bool operator!=(const FqElement& other) const {
        return value != other.value;
    }

    // -------------------- Static Methods -------------------- // 

    static FqElement random() {
        return FqElement(libff::alt_bn128_Fq::random_element());
    }

    static FqElement zero() {
        return FqElement(libff::alt_bn128_Fq::zero());
    }

    static FqElement one() {
        return FqElement(libff::alt_bn128_Fq::one());
    }
};
}
