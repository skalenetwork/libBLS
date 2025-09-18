#pragma once

#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "backends/algebra_types.hpp"
#include "backends/interface/curve_contract_altbn128.hpp"

namespace libBLS::algebra {

class FqElement : public Field< FqBackendType, FqElement > {
public:
    static constexpr size_t SIZE_BYTES = 32;
    static constexpr std::string_view EULER = AltBn128Contract::fq_euler_dec;

    FqElement();
    FqElement( uint64_t x );
    FqElement( const FqBackendType& val ) : Field( val ) {}

    // -------------------- Serialization / Deserialization Methods -------------------- //

    std::array< uint8_t, SIZE_BYTES > toByteArray() const;
    std::string toString( Base base ) const;

    static FqElement fromString( const std::string& str, Base base );
    static FqElement fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes );

    /**
     * Convert to uint64_t
     * If the value is larger than what can fit in uint64_t, apply modulo 2^64.
     * This is the same as returning the lowest 64 bits of the value.
     */
    uint64_t toUlong() const;

    // -------------------- Operator Overloads -------------------- //

    FqElement operator+( const FqElement& other ) const;
    FqElement operator-( const FqElement& other ) const;
    FqElement operator*( const FqElement& other ) const;
    FqElement& operator+=( const FqElement& other );
    FqElement operator^( const unsigned long pow ) const;
    FqElement& operator*=( const FqElement& other );
    bool operator==( const FqElement& other ) const;
    bool operator!=( const FqElement& other ) const;

    FqElement sqrt() const;

    // -------------------- Static Methods -------------------- //

    static FqElement random();
};

inline std::ostream& operator<<( std::ostream& os, FqElement const& element ) {
    // Choose HEX or DEC encoding depending on your needs
    return os << element.toString( libBLS::Base::HEXA );
}

class FqRefWrapper {
    FqBackendType& ref_;

public:
    explicit FqRefWrapper( FqBackendType& ref ) : ref_( ref ) {}
    FqBackendType& asBackendRef() { return ref_; }
};

}  // namespace libBLS::algebra
