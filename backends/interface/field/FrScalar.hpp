#pragma once

#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "backends/algebra_types.hpp"

namespace libBLS::algebra {

class FrScalar : public Field< FrBackendType, FrScalar > {
public:
    static const size_t SIZE_BYTES = 32;

    FrScalar();
    FrScalar( const size_t n );
    FrScalar( const FrBackendType& v ) : Field( v ) {}

    FrScalar inverse() const;

    // ---------- Serialization ----------- //

    std::vector< uint8_t > toByteVector() const;
    std::array< uint8_t, SIZE_BYTES > toByteArray() const;

    std::string toString( Base base ) const;

    // ---------- Deserialization ----------- //

    static FrScalar fromBytes( const std::array< uint8_t, SIZE_BYTES >& bytes );
    static FrScalar fromBytes( const std::vector< uint8_t >& bytes );

    static FrScalar fromString( const std::string& str, Base base );

    // -------------------- Static Methods -------------------- //

    static FrScalar random();

    // -------------------- Operator Overloads -------------------- //

    FrScalar operator+( const FrScalar& other ) const;
    FrScalar operator-( const FrScalar& other ) const;
    FrScalar operator-() const;
    FrScalar operator*( const FrScalar& other ) const;
    FrScalar operator+=( const FrScalar& other );
    FrScalar operator*=( const FrScalar& other );
    bool operator==( const FrScalar& other ) const;
    bool operator!=( const FrScalar& other ) const;
};

}  // namespace libBLS::algebra
