#pragma once

#include "../algebra_types.hpp"

namespace libBLS {
namespace algebra {

class FrScalar {

public:

#ifdef MCL
#else
    static const size_t SIZE_BYTES = 32;
#endif

    static const FrScalar ZERO;
    static const FrScalar ONE;

    FrBackendType value;

    FrScalar();
    FrScalar(const size_t n);
    FrScalar(const FrBackendType& v) : value(v) {}

    FrScalar inverse() const;

    bool isZero() const;

    // ---------- Serialization ----------- //

    std::vector< uint8_t > toByteVector() const;
    std::array< uint8_t, SIZE_BYTES > toByteArray() const;

    std::string toString( Base base ) const;

    // ---------- Deserialization ----------- //

    static FrScalar fromBytes(const std::array< uint8_t, SIZE_BYTES >& bytes);
    static FrScalar fromBytes(const std::vector< uint8_t >& bytes);

    static FrScalar fromString(const std::string& str, Base base);

    // -------------------- Static Methods -------------------- // 

    static FrScalar random();

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
