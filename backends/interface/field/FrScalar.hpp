#pragma once

#include <gmpxx.h>
#include "../WrapperCore.hpp"
#include "Field.hpp"
#include "backends/algebra_types.hpp"

namespace libBLS::algebra {

class FrScalar : public Field< FrBackendType, FrScalar > {
public:
    static const size_t SIZE_BYTES = 32;

private:
    mpz_class toMpzClass() const;
    static FrBackendType fromMpzClass( const mpz_class& m );

    static FrScalar fromBytesDefault( const std::array< uint8_t, SIZE_BYTES >& bytes ) {
        mpz_class t = bytesToMpzClass( bytes );
        return fromMpzClass(t);
    }

    static FrScalar fromBytesDefault( const std::vector< uint8_t >& bytes ) {
        mpz_class t = bytesToMpzClass( bytes );
        return fromMpzClass(t);
    }

    static FrScalar fromStringDefault( const std::string& str, Base base ) {
        mpz_class t = stringToMpzClass( str, static_cast< size_t >( base ) );
        return fromMpzClass(t);
    }

    std::vector< uint8_t > toByteVectorDefault() const {
        mpz_class t = toMpzClass();
        return mpzClassToByteVector( t );
    }

    std::array< uint8_t, SIZE_BYTES > toByteArrayDefault() const {
        mpz_class t = toMpzClass();
        return mpzClassToByteArray( t );
    }

    std::string toStringDefault( Base base ) const {
        mpz_class t = toMpzClass();
        return mpzClassToString( t, static_cast< size_t >( base ) );
    }

public:

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
