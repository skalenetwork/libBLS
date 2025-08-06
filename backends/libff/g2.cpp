#pragma once

#include "../interface/g2.hpp"
#include "../interface/fr.hpp"
#include "../interface/fq.hpp"
#include "../algebra_types.hpp"
#include "utils.hpp"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <tools/utils.h>

namespace libBLS {
namespace algebra {

G2Point::G2Point() {
    value = libff::alt_bn128_G2::zero();
}

void G2Point::to_affine_coordinates() {
    value.to_affine_coordinates();
}

// -------------------- Serialization Methods -------------------- //

std::string G2Point::toString(Base base) const {
    auto affineComponents = getAffineComponents();

    // build string as concatenatin of all affineComponents
    std::string result;
    for (const auto& comp : affineComponents) {
        result += comp.toString(base);
    }
    return result;
}

std::array<std::string, G2Point::NUM_SERIALIZED_COMPONENTS> G2Point::toStringArray(Base base) const {
    // apply affine coordinates to copy - keep current object const
    std::array<FqElement, NUM_SERIALIZED_COMPONENTS> affineComponents = getAffineComponents();
    return { 
        affineComponents[0].toString(base),
        affineComponents[1].toString(base), 
        affineComponents[2].toString(base), 
        affineComponents[3].toString(base) 
    };
}

std::array< uint8_t, G2Point::SIZE_BYTES > G2Point::toByteArray() const {
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

std::vector< uint8_t > G2Point::toByteVector() const {
    std::array< uint8_t, SIZE_BYTES > bytes = toByteArray();
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

bool G2Point::isValid() const {
    return !is_zero() && is_well_formed() && is_in_group();
}

void G2Point::validate() const {
    if ( is_zero() ) {
        throw ThresholdUtils::IncorrectInput( "Point is zero" );
    }
    if ( !is_well_formed() ) {
        throw ThresholdUtils::IncorrectInput( "Point is not well formed" );
    }
    if ( !is_in_group() ) {
        throw ThresholdUtils::IncorrectInput( "Point is not on the group" );
    }
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

G2Point G2Point::fromBytes(const std::array<uint8_t, G2Point::SIZE_BYTES>& bytes) {
    const size_t FQ_SIZE_BYTES = FqElement::SIZE_BYTES;
    std::array< uint8_t, FQ_SIZE_BYTES > currentField;

    algebra::G2Point ret;
    ret.value.Z = libff::alt_bn128_Fq2::one();

    const uint8_t* source = bytes.data();

    // Get x.c0
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.X.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get x.c1
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.X.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get y.c0
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.Y.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );
    source += FQ_SIZE_BYTES;

    // Get y.c1
    std::memcpy( currentField.data(), source, FQ_SIZE_BYTES );
    ret.value.Y.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( currentField );

    return ret;
}

G2Point G2Point::fromBytes(const std::vector< uint8_t >& bytes ) {
    if ( bytes.size() != SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Incorrect number of bytes" );
    }

    std::array< uint8_t, SIZE_BYTES > G2Bytes;
    std::copy( bytes.begin(), bytes.end(), G2Bytes.begin() );

    return fromBytes( G2Bytes );
}

G2Point G2Point::fromString(const std::string& str, Base base ) {
    if ( base != libBLS::Base::HEXA ) {
        throw ThresholdUtils::IncorrectInput( "G2Point is currently only supported to be built from hexadecimal base string" );
    }

    const size_t stringSize = 256;
    const size_t elementStringSize = 64;

    if ( str.size() != stringSize ) {
        throw ThresholdUtils::IncorrectInput( "Wrong string size to convert to G2" );
    }

    algebra::G2Point ret;

    ret.value.Z = libff::alt_bn128_Fq2::one();

    ret.value.X.c0 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 0 * elementStringSize, elementStringSize ) ).c_str() );
    ret.value.X.c1 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 1 * elementStringSize, elementStringSize ) ).c_str() );
    ret.value.Y.c0 =
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 2 * elementStringSize, elementStringSize ) ).c_str() );
    ret.value.Y.c1 = 
        libff::alt_bn128_Fq( ThresholdUtils::convertHexToDec( str.substr( 3 * elementStringSize , std::string::npos ) ).c_str() );

    return ret;
}

G2Point G2Point::fromString(const std::array<std::string, NUM_SERIALIZED_COMPONENTS>& arr, Base base) {
    algebra::G2Point ret;
    ret.value.Z = libff::alt_bn128_Fq2::one();

    switch (base) {
        case Base::HEXA:

            std::array< std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >, 4 > components;
            // convert from hexa to bytes
            for ( size_t i = 0; i < arr.size(); ++i ) {
                if ( arr[i].length() != MAX_FIELD_ELEMENT_SIZE_BYTES * 2 ) {
                    throw ThresholdUtils::IncorrectInput( "wrong string length in public key share" );
                }
                // throws if cannot hexa is not valid
                components[i] = ThresholdUtils::hexCStringToBytesArray< MAX_FIELD_ELEMENT_SIZE_BYTES >(
                    arr[i].c_str() );
            }

            ret.value.X.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( components[0] );
            ret.value.X.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( components[1] );
            ret.value.Y.c0 = bytesToFieldElement< libff::alt_bn128_Fq >( components[2] );
            ret.value.Y.c1 = bytesToFieldElement< libff::alt_bn128_Fq >( components[3] );
            break;
        case Base::DEC:
            ret.value.X.c0 = libff::alt_bn128_Fq( arr[0].c_str() );
            ret.value.X.c1 = libff::alt_bn128_Fq( arr[1].c_str() );
            ret.value.Y.c0 = libff::alt_bn128_Fq( arr[2].c_str() );
            ret.value.Y.c1 = libff::alt_bn128_Fq( arr[3].c_str() );
            break;
        default:
            throw ThresholdUtils::IncorrectInput("Unsupported base");
    }
    return ret;
}

G2Point G2Point::fromString(const std::vector<std::string>& arr, Base base) {
    if ( arr.size() != NUM_SERIALIZED_COMPONENTS ) {
        throw ThresholdUtils::IncorrectInput( "Wrong number of components in G2Point" );
    }
    std::array<std::string, NUM_SERIALIZED_COMPONENTS> arrCopy;
    std::copy(arr.begin(), arr.end(), arrCopy.begin());
    return fromString(arrCopy, base);
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
