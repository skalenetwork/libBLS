#pragma once

#include <array>
#include <vector>

#include "backends/algebra.hpp"
#include "AesGcmCipher.h"

namespace libBLS {

/**
 * @brief Holds the AES key ciphered via
 * Threshold Encryption
 */
struct CipheredKey {
    static constexpr size_t CIPHERED_KEY_SIZE_BYTES =
        algebra::G2Point::SIZE_BYTES + AES_256_KEY_SIZE_BYTES + algebra::G1Point::SIZE_BYTES;

    algebra::G2Point U;
    AES256Key V;
    algebra::G1Point W;

public:
    CipheredKey() = default;
    CipheredKey( algebra::G2Point _U, AES256Key _V, algebra::G1Point _W, bool _validate = true )
        : U( _U ), V( std::move( _V ) ), W( _W ) {
        if ( _validate )
            validate();
    }

    bool operator==( const CipheredKey& other ) const {
        return ( U == other.U ) && ( V == other.V ) && ( W == other.W );
    }

    /**
     * @brief Converts CipheredKey to bytes
     * The byte format returned is: `[ U | V | W ]`
     * where `U` and `W` are elements of G2 and G1 groups respectively,
     * and `V` is a fixed size AES256Key.
     *
     * Final byte representation is always of fixed size.
     */
    std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > toBytes() const;

    /**
     * @brief Converts bytes to CipheredKey
     */
    static CipheredKey fromBytes(
        std::array< uint8_t, CIPHERED_KEY_SIZE_BYTES > _bytes, bool _validate = true );

    /**
     * @brief Validates the CipheredKey
     * @throw NotWellFormed if the key is not well formed
     */
    void validate() const;

    static CipheredKey random();

    /**
     * Converts U component of the key to string
     */
    std::string getDecryptionShareInput();

    static std::vector< std::string > getDecryptionShareInputBatch(
        const std::vector< CipheredKey >& keys );

    const algebra::G2Point& getU() const { return U; }
    const AES256Key& getV() const { return V; }
    const algebra::G1Point& getW() const { return W; }
};

} // namespace libBLS
