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

const G2Point G2Point::ZERO = G2Point(libff::alt_bn128_G2::zero());
const G2Point G2Point::ONE = G2Point(libff::alt_bn128_G2::one());

G2Point::G2Point() {
    value = libff::alt_bn128_G2::zero();
}

G2Point::G2Point(const Fq2Element& x, const Fq2Element& y, const Fq2Element& z) {
    value.X.c0 = x.c0.value;
    value.X.c1 = x.c1.value;
    value.Y.c0 = y.c0.value;
    value.Y.c1 = y.c1.value;
    value.Z.c0 = z.c0.value;
    value.Z.c1 = z.c1.value;
}

void G2Point::toAffineCoordinates() {
    value.to_affine_coordinates();
}

// -------------------- Serialization Methods -------------------- //

std::string G2Point::toString(Base base) const {
    if ( base != libBLS::Base::HEXA ) {
        throw ThresholdUtils::IncorrectInput( "G2Point to string is only supported in HEXA base" );
    }

    auto affineComponents = getAffineComponents();

    // build string as concatenatin of all affineComponents
    std::string result;
    for (const auto& comp : affineComponents) {
        result += comp.toString(base);
    }
    return result;
}

std::array<std::string, G2Point::NUM_COMPONENTS_AFFINE> G2Point::toStringArray(Base base) const {
    // apply affine coordinates to copy - keep current object const
    std::array<FqElement, NUM_COMPONENTS_AFFINE> affineComponents = getAffineComponents();
    return { 
        affineComponents[0].toString(base),
        affineComponents[1].toString(base), 
        affineComponents[2].toString(base), 
        affineComponents[3].toString(base) 
    };
}

std::array<std::string, G2Point::NUM_COMPONENTS_PROJECTIVE> G2Point::toStringArrayProjective(Base base) const {
    // apply affine coordinates to copy - keep current object const
    std::array<FqElement, NUM_COMPONENTS_PROJECTIVE> projectiveComponents = getProjectiveComponents();
    return { 
        projectiveComponents[0].toString(base),
        projectiveComponents[1].toString(base), 
        projectiveComponents[2].toString(base), 
        projectiveComponents[3].toString(base), 
        projectiveComponents[4].toString(base), 
        projectiveComponents[5].toString(base)
    };
}

std::vector<std::string> G2Point::toStringVector(Base base) const {
    // apply affine coordinates to copy - keep current object const
    std::array<FqElement, NUM_COMPONENTS_AFFINE> affineComponents = getAffineComponents();
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

bool G2Point::isZero() const {
    return value.is_zero();
}

bool G2Point::isWellFormed() const {
    return value.is_well_formed();
}

bool G2Point::isInGroup() const {
    return libff::alt_bn128_G2::order() * value == libff::alt_bn128_G2::zero();
}

bool G2Point::isValid() const {
    return !isZero() && isWellFormed() && isInGroup();
}

void G2Point::validate() const {
    if ( isZero() ) {
        throw ThresholdUtils::IncorrectInput( "Point is zero" );
    }
    if ( !isWellFormed() ) {
        throw ThresholdUtils::IncorrectInput( "Point is not well formed" );
    }
    if ( !isInGroup() ) {
        throw ThresholdUtils::IncorrectInput( "Point is not on the group" );
    }
}

std::array<FqElement, G2Point::NUM_COMPONENTS_AFFINE> G2Point::getAffineComponents() const {
    libff::alt_bn128_G2 copy = value;
    copy.to_affine_coordinates();
    return { 
        FqElement(copy.X.c0), 
        FqElement(copy.X.c1), 
        FqElement(copy.Y.c0), 
        FqElement(copy.Y.c1) 
    };
}

std::array<FqElement, 6> G2Point::getProjectiveComponents() const {
    return { 
        FqElement(value.X.c0), 
        FqElement(value.X.c1), 
        FqElement(value.Y.c0), 
        FqElement(value.Y.c1),
        FqElement(value.Z.c0),
        FqElement(value.Z.c1)
    };
}

// -------------------- Static Methods -------------------- //

G2Point G2Point::random() {
    return G2Point(libff::alt_bn128_G2::random_element());
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

G2Point G2Point::fromString(const std::array<std::string, NUM_COMPONENTS_AFFINE >& arr, Base base) {
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
    if ( arr.size() != NUM_COMPONENTS_AFFINE) {
        throw ThresholdUtils::IncorrectInput( "Wrong number of components in G2Point" );
    }
    std::array<std::string, NUM_COMPONENTS_AFFINE> arrCopy;
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


G2Point operator*(const FrScalar& scalar, const G2Point& point) {
    return scalar.value * point.value;
}

} // namespace algebra
} // namespace libBLS
