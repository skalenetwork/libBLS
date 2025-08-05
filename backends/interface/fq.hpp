#pragma once

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#endif

namespace libBLS {
namespace algebra {

class FqElement {

public:
#ifdef MCL
#else
    static constexpr size_t SIZE_BYTES = 32;
    libff::alt_bn128_Fq value;

    FqElement(const libff::alt_bn128_Fq& val) : value(val) {}
#endif

    FqElement();
    FqElement(uint64_t x);
    FqElement(const std::string& str);

    // -------------------- Operator Overloads -------------------- //

    FqElement operator+(const FqElement& other) const;
    FqElement operator-(const FqElement& other) const;
    FqElement operator*(const FqElement& other) const;
    FqElement& operator+=(const FqElement& other);
    FqElement operator^(const unsigned long pow) const;
    FqElement& operator*=(const FqElement& other);
    bool operator==(const FqElement& other) const;
    bool operator!=(const FqElement& other) const;

    // -------------------- Static Methods -------------------- // 

    static FqElement random();
    static FqElement zero();
    static FqElement one();
};

} // namespace algebra
} // namespace libBLS
