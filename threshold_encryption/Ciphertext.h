#pragma once

#include <memory>
#include <vector>

#include <tools/utils.h>

#include "CipheredKey.h"
#include "TEVersion.h"

namespace libBLS {

constexpr size_t RANDOM_SECRET_SIZE_BYTES = MAX_FIELD_ELEMENT_SIZE_BYTES;

/**
 * @brief Holds ciphered AES key(s) and the AES-GCM encrypted payload.
 *
 * Wire Format Layout:
 *   [ Header | Key_1 | (Key_2) | AES_Payload ]
 *
 * Header (1 byte):
 *   - Bits [7..2] (6 bits): Format Version
 *      - 0x00: V0: Legacy ASCII mask
 *      - 0x01: V1: Moved AES256 from 128 bits to 256 bit entropy
 *      - Anything over 0x01: reserved for future versions parsed as invalid currently.
 *   - Bits [1..0] (2 bits): Number of encapsulated keys
 *      - 0x00: invalid
 *      - 0x01: 1 key
 *      - 0x02: 2 keys
 *      - 0x03: invalid
 *
 * Encapsulated Keys (CipheredKey, 224 bytes each):
 *   - U (128 bytes): Ephemeral G2 curve point
 *   - V (32 bytes): Masked AES-256 key
 *   - W (64 bytes): Proof G1 curve point
 *
 * AES_Payload (variable size):
 *   - IV (12 bytes) + Ciphertext (Plaintext + 32-byte RandSecret) + Auth Tag (16 bytes)
 */
struct Ciphertext {
    enum class KeyCount : uint8_t {
        ONE = 0x01,
        TWO = 0x02,
    };

    std::vector< CipheredKey > keys;
    std::shared_ptr< std::vector< uint8_t > > data;
    TEVersion version = LATEST_TE_VERSION;


public:
    bool operator==( const Ciphertext& other ) const {
        bool baseParams = ( version == other.version ) && ( keys == other.keys );
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }

    Ciphertext() = default;

    Ciphertext( const std::vector< CipheredKey >& _keys, const std::vector< uint8_t >& _data,
        bool _validate = true, TEVersion _version = LATEST_TE_VERSION )
        : keys( _keys ),
          data( std::make_shared< std::vector< uint8_t > >( _data ) ),
          version( _version ) {
        if ( _validate )
            validate();
    }

    Ciphertext( const CipheredKey& _key, const std::vector< uint8_t >& _data,
        bool _validate = true, TEVersion _version = LATEST_TE_VERSION )
        : keys( { _key } ),
          data( std::make_shared< std::vector< uint8_t > >( _data ) ),
          version( _version ) {
        if ( _validate )
            validate();
    }

    // Constructor for exactly two keys
    Ciphertext( const CipheredKey& _key1, const CipheredKey& _key2,
        const std::vector< uint8_t >& _data, bool _validate = true,
        TEVersion _version = LATEST_TE_VERSION )
        : keys( { _key1, _key2 } ),
          data( std::make_shared< std::vector< uint8_t > >( _data ) ),
          version( _version ) {
        if ( _validate )
            validate();
    }

    const std::vector< uint8_t >& getData() const;

    const std::vector< uint8_t > toBytes() const;

    static Ciphertext fromBytes( const std::vector< uint8_t >& bytes, bool _validate = true );

    /**
     * @brief Validates the Ciphertext
     * @throw NotWellFormed if the it fails the validation
     */
    void validate() const;

    /**
     * @brief Returns the vector of keys in the Ciphertext
     */
    const std::vector< CipheredKey >& getKeys() const;

    /**
     * @brief keeps only one key for validation and decryption
     * @param idx - index of the key to keep
     */
    void keepKey( size_t _idx );

    /**
     * @brief get a CipheredKey for validation and decryption
     * @throw IncorrectInput if there are 0 or 2 keys to choose
     */
    const CipheredKey& getTargetKey() const;

    TEVersion getVersion() const { return version; }

private:
    static constexpr uint8_t HEADER_SIZE = sizeof( uint8_t );
    static constexpr uint8_t VERSION_SHIFT_BITS = 2;
    static constexpr uint8_t KEY_COUNT_MASK = 0x03;  // 0000 0011
    static constexpr uint8_t VERSION_MASK   = 0xFC;  // 1111 1100

    static uint8_t buildHeader( TEVersion version, KeyCount keyCount );
    static std::pair< TEVersion, KeyCount > parseHeader( uint8_t header );

    void validateVersionConsistency() const;
};

}  // namespace libBLS
