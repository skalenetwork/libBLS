#pragma once

#include "../algebra_types.hpp"

namespace libBLS {
namespace algebra {

class FqElement {

public:
#ifdef MCL
#else
    static constexpr size_t SIZE_BYTES = 32;
#endif

    static const FqElement ZERO;
    static const FqElement ONE;

    FqBackendType value;

    FqElement();
    FqElement(uint64_t x);
    FqElement(const FqBackendType& val) : value(val) {}

    // -------------------- Serialization / Deserialization Methods -------------------- //
    std::string toString(Base base) const;

    static FqElement fromString(const std::string& str, Base base);

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

    static FqElement fromHash(const std::array< uint8_t, HASH_SIZE>& hash_byte_arr);
};

class FqRefWrapper {
    FqBackendType ref_;
public:
    explicit FqRefWrapper(FqBackendType& ref) : ref_(ref) {}
    FqBackendType& asBackendRef() { return ref_; }
};

} // namespace algebra
} // namespace libBLS
