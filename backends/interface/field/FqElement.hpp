#pragma once

#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "backends/interface/curve_contract_altbn128.hpp"
#include "backends/algebra_types.hpp"

namespace libBLS::algebra {

class FqElement : public Field< FqBackendType, FqElement > {
public:
    static constexpr size_t SIZE_BYTES = 32;
    static constexpr std::string_view EULER = AltBn128Contract::fq_euler_dec;

    FqElement();
    FqElement( uint64_t x );
    FqElement( const FqBackendType& val ) : Field( val ) {}

    // -------------------- Serialization / Deserialization Methods -------------------- //
    std::string toString( Base base ) const;
    std::array< uint8_t, SIZE_BYTES > toByteArray() const;

    static FqElement fromString( const std::string& str, Base base );
    static FqElement fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes );


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

class FqRefWrapper {
    FqBackendType& ref_;

public:
    explicit FqRefWrapper( FqBackendType& ref ) : ref_( ref ) {}
    FqBackendType& asBackendRef() { return ref_; }
};

}  // namespace libBLS::algebra
