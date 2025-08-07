#pragma once

#include "fr.hpp"
#include "fq.hpp"
#include "fq2.hpp"
#include "../algebra_types.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif 

namespace libBLS {
namespace algebra {

class G2Point {

public:

    static constexpr std::size_t NUM_COMPONENTS_AFFINE = 4;
    static constexpr std::size_t NUM_COMPONENTS_PROJECTIVE = 6;

#ifdef MCL
#else
    static constexpr std::size_t SIZE_BYTES = 128;
#endif

    G2BackendType value;

    static const G2Point ZERO;
    static const G2Point ONE;

    G2Point();
    G2Point(const G2BackendType v) : value(v) {}
    G2Point( const Fq2Element& x, const Fq2Element& y, const Fq2Element& z);


    void toAffineCoordinates();

    // -------------------- Serialization Methods -------------------- //

    std::array<std::string, NUM_COMPONENTS_AFFINE> toStringArray(Base base) const;
    std::array<std::string, NUM_COMPONENTS_PROJECTIVE> toStringArrayProjective( Base base ) const;
    // TODO - get rid of this method - should only return array
    std::vector< std::string > toStringVector(Base base) const;

    std::string toString(Base base) const;

    std::array< uint8_t, SIZE_BYTES > toByteArray() const;
    std::vector< uint8_t > toByteVector() const;

    // ------------------- Getters ------------------- //

    Fq2RefWrapper getXRef() { return Fq2RefWrapper(value.X); }
    Fq2RefWrapper getYRef() { return Fq2RefWrapper(value.Y); }
    Fq2RefWrapper getZRef() { return Fq2RefWrapper(value.Z); }

    // -------------------- Validation Methods -------------------- //

    bool isZero() const;
    bool isWellFormed() const;
    bool isInGroup() const;
    bool isValid() const;
    void validate() const;

    std::array<FqElement, NUM_COMPONENTS_AFFINE> getAffineComponents() const ;
    std::array<FqElement, NUM_COMPONENTS_PROJECTIVE> getProjectiveComponents() const;

    // -------------------- Static Methods -------------------- //

    static G2Point random();

    static G2Point fromBytes(const std::array<uint8_t, SIZE_BYTES>& bytes);
    static G2Point fromBytes(const std::vector< uint8_t >& bytes );

    static G2Point fromString(const std::string& str, Base base );
    static G2Point fromString(const std::array<std::string, NUM_COMPONENTS_AFFINE>& arr, Base base);
    // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the size
    static G2Point fromString(const std::vector<std::string>& arr, Base base);

    // -------------------- Operator Overloads -------------------- //

    G2Point operator+(const G2Point& other) const;
    G2Point operator-(const G2Point& other) const;
    bool operator==(const G2Point& other) const;
    bool operator!=(const G2Point& other) const;

};

G2Point operator*(const FrScalar& scalar, const G2Point& point);

} // namespace algebra
} // namespace libBLS

