#pragma once

#include "../interface/g2.hpp"
#include "../interface/fr.hpp"
#include "../interface/fq.hpp"
#include "../algebra_types.hpp"
#include "utils.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {
namespace algebra {

G2Point::G2Point() {
    value = libff::alt_bn128_G2::zero();
}

void G2Point::to_affine_coordinates() {
    value.to_affine_coordinates();
}

G2Point::G2Point(const std::array< std::string, G2Point::NUM_SERIALIZED_COMPONENTS >& serializedG2) {
    value.X.c0 = libff::alt_bn128_Fq( serializedG2.at( 0 ).c_str() );
    value.X.c1 = libff::alt_bn128_Fq( serializedG2.at( 1 ).c_str() );
    value.Y.c0 = libff::alt_bn128_Fq( serializedG2.at( 2 ).c_str() );
    value.Y.c1 = libff::alt_bn128_Fq( serializedG2.at( 3 ).c_str() );
    value.Z.c0 = libff::alt_bn128_Fq::one();
    value.Z.c1 = libff::alt_bn128_Fq::zero();
}

// -------------------- Serialization Methods -------------------- //

std::array<std::string, G2Point::NUM_SERIALIZED_COMPONENTS> G2Point::toStringArray(libBLS::Base base) const {
    // apply affine coordinates to copy - keep current object const
    std::array<FqElement, NUM_SERIALIZED_COMPONENTS> affineComponents = getAffineComponents();
    size_t sizeBase = static_cast<size_t>(base);
    return { 
        fieldElementToString( affineComponents[0].value, sizeBase ), 
        fieldElementToString( affineComponents[1].value, sizeBase ),
        fieldElementToString( affineComponents[2].value, sizeBase ), 
        fieldElementToString( affineComponents[3].value, sizeBase ) 
    };
}

std::array< uint8_t, G2Point::SIZE_BYTES > G2Point::toBytesArray() const {
    std::array< uint8_t, SIZE_BYTES > G2Bytes;
    auto affine = getAffineComponents();
    uint8_t* dest = G2Bytes.data();

    for (const FqElement& part : affine) {
        auto partBytes = fieldElementToBytes(part.value);
        std::memcpy(dest, partBytes.data(), FqElement::SIZE_BYTES);
        dest += FqElement::SIZE_BYTES;
    }

    return G2Bytes;
}

std::vector< uint8_t > G2Point::toBytesVector() const {
    std::array< uint8_t, SIZE_BYTES > bytes = toBytesArray();
    return std::vector< uint8_t >( bytes.begin(), bytes.end() );
}

// -------------------- Validation Methods -------------------- //

bool G2Point::is_zero() const {
    return value.is_zero();
}

bool G2Point::is_well_formed() const {
    return value.is_well_formed();
}

bool G2Point::is_in_group() const {
    return libff::alt_bn128_G2::order() * value == libff::alt_bn128_G2::zero();
}

std::array<FqElement, 4> G2Point::getAffineComponents() const {
    return { FqElement(value.X.c0), FqElement(value.X.c1), FqElement(value.Y.c0), FqElement(value.Y.c1) };
}

// -------------------- Static Methods -------------------- //

G2Point G2Point::random() {
    return G2Point(libff::alt_bn128_G2::random_element());
}

G2Point G2Point::zero() {
    return G2Point(libff::alt_bn128_G2::zero());
}

G2Point G2Point::one() {
    return G2Point(libff::alt_bn128_G2::one());
}

// -------------------- Operator Overloads -------------------- //

G2Point G2Point::operator+(const G2Point& other) const {
    return G2Point(value + other.value);
}

G2Point G2Point::operator-(const G2Point& other) const {
    return G2Point(value - other.value);
}

bool G2Point::operator==(const G2Point& other) const {
    return value == other.value;
}

bool G2Point::operator!=(const G2Point& other) const {
    return value != other.value;
}


inline G2Point operator*(const FrScalar& scalar, const G2Point& point) {
    return scalar.value * point.value;
}

} // namespace algebra
} // namespace libBLS
