#pragma once

#include "../WrapperCore.hpp"
#include "backends/algebra_types.hpp"

namespace libBLS {
namespace algebra {

class FqElement : public WrapperCore< FqBackendType, FqElement > {
public:
#ifdef MCL
#else
    static constexpr size_t SIZE_BYTES = 32;
#endif

    FqElement();
    FqElement( uint64_t x );
    FqElement( const FqBackendType& val ) : WrapperCore( val ) {}

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

    // -------------------- Static Methods -------------------- //

    static FqElement random();

    static FqElement fromHash( const std::array< uint8_t, HASH_SIZE >& hash_byte_arr );
};

class FqRefWrapper {
    FqBackendType& ref_;

public:
    explicit FqRefWrapper( FqBackendType& ref ) : ref_( ref ) {}
    FqBackendType& asBackendRef() { return ref_; }
};

}  // namespace algebra
}  // namespace libBLS
