#pragma once

#include <memory>
#include <vector>

#include <tools/utils.h>

#include "CipheredKey.h"

namespace libBLS {

constexpr size_t RANDOM_SECRET_SIZE_BYTES = MAX_FIELD_ELEMENT_SIZE_BYTES;

/**
 * @brief Holds the ciphered AES keys (vector), as well as the data
 * ciphered with AES key.
 */
struct Ciphertext {
    std::vector< CipheredKey > keys;
    std::shared_ptr< std::vector< uint8_t > > data;

public:
    bool operator==( const Ciphertext& other ) const {
        bool baseParams = keys == other.keys;
        if ( data && other.data ) {
            return baseParams && ( *data == *other.data );
        }
        return baseParams;
    }

    Ciphertext() = default;

    Ciphertext( const std::vector< CipheredKey >& _keys, const std::vector< uint8_t >& _data,
        bool _validate = true )
        : keys( _keys ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    Ciphertext(
        const CipheredKey& _key, const std::vector< uint8_t >& _data, bool _validate = true )
        : keys( { _key } ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    // Constructor for exactly two keys
    Ciphertext( const CipheredKey& _key1, const CipheredKey& _key2,
        const std::vector< uint8_t >& _data, bool _validate = true )
        : keys( { _key1, _key2 } ), data( std::make_shared< std::vector< uint8_t > >( _data ) ) {
        if ( _validate )
            validate();
    }

    const std::vector< uint8_t >& getData() const;

    /**
     * @brief Converts Ciphertext to bytes
     * The byte format returned is: `[ num_keys | key1 | key2 | ... | data ]`
     *
     * where `data` can be of arbitrary size, each `key` is a fixed size,
     * and `num_keys` is a 1-byte integer indicating the number of keys.
     */
    const std::vector< uint8_t > toBytes() const;

    /**
     * @brief Converts bytes to Ciphertext
     */
    static Ciphertext fromBytes( std::vector< uint8_t >& bytes, bool _validate = true );

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
};

}  // namespace libBLS
