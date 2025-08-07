#pragma once

#include "fq.hpp"
#include "../algebra_types.hpp"

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
    static constexpr size_t SIZE_BYTES = 64;
#endif

    static const G1Point ZERO;
    static const G1Point ONE;

    G1BackendType value;

    G1Point();
    G1Point(const FqElement& x, const FqElement& y);
    G1Point(const G1BackendType& v) : value(v) {}

    void toAffineCoordinates();
    bool isZero() const;
    bool isWellFormed() const;
    bool isInGroup() const;
    bool isValid() const;
    void validate() const;

    FqElement getX() const;
    FqElement getY() const;

    FqRefWrapper getXRef() { return FqRefWrapper(value.X); }
    FqRefWrapper getYRef() { return FqRefWrapper(value.Y); }
    FqRefWrapper getZRef() { return FqRefWrapper(value.Z); }

    // --------------------- Serialization Methods -------------------- //
    std::array< uint8_t, SIZE_BYTES > toByteArray() const;
    std::vector< uint8_t > toBytesVector() const;

    // --------------------- Static Methods -------------------- //

    static G1Point random();

    static G1Point fromBytes(const std::array<uint8_t, SIZE_BYTES>& bytes);
    static G1Point fromBytes(const std::vector<uint8_t>& bytes);
    static G1Point fromString(const std::string& str, Base base);
    static G1Point fromHash(const std::array< uint8_t, HASH_SIZE >& hash_byte_arr);
    static G1Point fromHash(const std::string& message);
    
    // -------------------- Operator Overloads -------------------- //

    G1Point operator+(const G1Point& other) const;
    G1Point operator-(const G1Point& other) const;
    bool operator==(const G1Point& other) const;
    bool operator!=(const G1Point& other) const;

};

G1Point operator*(const FrScalar& scalar, const G1Point& point);

} // namespace algebra
} // namespace libBLS
