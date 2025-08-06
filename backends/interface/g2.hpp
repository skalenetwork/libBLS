#pragma once

#include "fr.hpp"
#include "fq.hpp"
#include "../algebra_types.hpp"

#ifdef MCL
#else
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif 

namespace libBLS {
namespace algebra {

class G2Point {

public:

#ifdef MCL
#else
    static constexpr std::size_t SIZE_BYTES = 128;
    static constexpr std::size_t NUM_SERIALIZED_COMPONENTS = 4;
    
    libff::alt_bn128_G2 value;
    
    G2Point(const libff::alt_bn128_G2& v) : value(v) {}
#endif

    G2Point();

    // Builds a G2Point from its affine coordinates
    G2Point(const std::array< std::string, NUM_SERIALIZED_COMPONENTS >& serializedG2);

    
    void to_affine_coordinates();

    // -------------------- Serialization Methods -------------------- //

    std::array<std::string, NUM_SERIALIZED_COMPONENTS> toStringArray(libBLS::Base base) const;
    std::string toString(Base base) const;

    std::array< uint8_t, SIZE_BYTES > toByteArray() const;
    std::vector< uint8_t > toByteVector() const;

    // -------------------- Validation Methods -------------------- //

    bool is_zero() const;
    bool is_well_formed() const;
    bool is_in_group() const;
    bool isValid() const;
    void validate() const;

    std::array<FqElement, 4> getAffineComponents() const ;

    // -------------------- Static Methods -------------------- //

    static G2Point random();
    static G2Point zero();
    static G2Point one();

    static G2Point fromBytes(const std::array<uint8_t, SIZE_BYTES>& bytes);
    static G2Point fromBytes(const std::vector< uint8_t >& bytes );

    static G2Point fromString(const std::string& str, Base base );
    static G2Point fromString(const std::array<std::string, NUM_SERIALIZED_COMPONENTS>& arr, Base base);
    // TODO - we should get rid of this for perf. reasons. no need to use vectors when we know the size
    static G2Point fromString(const std::vector<std::string>& arr, Base base);

    // -------------------- Operator Overloads -------------------- //

    G2Point operator+(const G2Point& other) const;
    G2Point operator-(const G2Point& other) const;
    bool operator==(const G2Point& other) const;
    bool operator!=(const G2Point& other) const;

};

inline G2Point operator*(const FrScalar& scalar, const G2Point& point);

} // namespace algebra
} // namespace libBLS

