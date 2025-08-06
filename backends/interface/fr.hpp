#pragma once

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/utils.hpp>
#endif

namespace libBLS {
namespace algebra {

class FrScalar {

public:
#ifdef MCL
#else
    static constexpr size_t SIZE_BYTES = 32;
    libff::alt_bn128_Fr value;

    FrScalar(const libff::alt_bn128_Fr& v) : value(v) {}

#endif

    FrScalar();
    FrScalar(const size_t n);
    FrScalar(const std::string& str);

    FrScalar inverse() const;

    bool is_zero() const;

    std::array< uint8_t, SIZE_BYTES > toByteArray() const;

    // -------------------- Static Methods -------------------- // 

    static FrScalar random();
    static FrScalar zero();
    static FrScalar one();

    static FrScalar fromByteArray(const std::array< uint8_t, SIZE_BYTES >& bytes);

    // -------------------- Operator Overloads -------------------- //

    FrScalar operator+(const FrScalar& other) const;
    FrScalar operator-(const FrScalar& other) const;
    FrScalar operator*(const FrScalar& other) const;
    FrScalar operator+=(const FrScalar& other);
    FrScalar operator*=(const FrScalar& other);
    bool operator==(const FrScalar& other) const;
    bool operator!=(const FrScalar& other) const;
};

} // namespace algebra
} // namespace libBLS
