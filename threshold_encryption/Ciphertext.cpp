#include "Ciphertext.h"

namespace libBLS {

const std::vector< uint8_t >& Ciphertext::getData() const {
    if ( !data ) {
        throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
    }
    return *data;
}


const std::vector< uint8_t > Ciphertext::toBytes() const {
    if ( !data ) {
        throw ThresholdUtils::IncorrectInput( "Cyphertext data is not initialized" );
    }

    // Calculate total size needed
    size_t totalSize = sizeof( uint8_t ) +  // for number of keys
                       ( keys.size() * CipheredKey::CIPHERED_KEY_SIZE_BYTES ) +  // for all keys
                       data->size();                                             // for data

    std::vector< uint8_t > bytes;
    bytes.reserve( totalSize );

    // Add number of keys
    uint8_t numKeys = static_cast< uint8_t >( keys.size() );
    bytes.push_back( numKeys );

    // Add each key
    for ( const auto& key : keys ) {
        std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes = key.toBytes();
        bytes.insert( bytes.end(), keyBytes.begin(), keyBytes.end() );
    }

    // Add data
    bytes.insert( bytes.end(), data->begin(), data->end() );

    return bytes;
}


Ciphertext Ciphertext::fromBytes( std::vector< uint8_t >& bytes, bool _validate ) {
    // we require at least 1 byte for num_keys + one key + random secret + 1 byte for data
    if ( bytes.size() <=
         sizeof( uint8_t ) + CipheredKey::CIPHERED_KEY_SIZE_BYTES + RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Cyphertext data is too short" );
    }

    size_t offset = 0;

    // Get number of keys
    uint8_t numKeys;
    std::memcpy( &numKeys, bytes.data() + offset, sizeof( uint8_t ) );
    offset += sizeof( uint8_t );

    if ( numKeys == 0 || numKeys > 2 )
        throw ThresholdUtils::IncorrectInput( "Ciphertext must contain exactly 1 or 2 keys" );

    // Check that the input matches the number of keys
    size_t expectedMinSize = sizeof( uint8_t ) +
                             ( numKeys * CipheredKey::CIPHERED_KEY_SIZE_BYTES ) +
                             RANDOM_SECRET_SIZE_BYTES + 1;  // +1 for at least 1 byte of actual data
    if ( bytes.size() < expectedMinSize )
        throw ThresholdUtils::IncorrectInput(
            "Cyphertext data is too short for specified number of keys" );

    // Extract keys
    std::vector< CipheredKey > keys;
    keys.reserve( numKeys );

    for ( size_t i = 0; i < numKeys; ++i ) {
        std::array< uint8_t, CipheredKey::CIPHERED_KEY_SIZE_BYTES > keyBytes;
        std::memcpy( keyBytes.data(), bytes.data() + offset, CipheredKey::CIPHERED_KEY_SIZE_BYTES );
        offset += CipheredKey::CIPHERED_KEY_SIZE_BYTES;

        // do not validate CipheredKey here
        // if validation is enabled, CipheredKey is validated in Ciphertext's constructor
        // otherwise we don't need validation at all
        keys.push_back( CipheredKey::fromBytes( keyBytes, false ) );
    }

    // Get data bytes
    std::vector< uint8_t > data( bytes.begin() + offset, bytes.end() );

    return Ciphertext( keys, data, _validate );
}

void Ciphertext::validate() const {
    if ( keys.empty() || keys.size() > 2 )
        throw ThresholdUtils::IsNotWellFormed( "Ciphertext must contain exactly 1 or 2 keys" );

    for ( const auto& key : keys ) {
        key.validate();
    }

    if ( !data ) {
        throw ThresholdUtils::IsNotWellFormed( "Cyphertext data is not initialized" );
    }

    // actual data without random secret must be at least 1 byte long
    if ( data->size() <= RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IsNotWellFormed(
            "Cyphertext data is too short to hold random secret and at least 1 byte of data." );
    }
}

const std::vector< CipheredKey >& Ciphertext::getKeys() const {
    return keys;
}

void Ciphertext::keepKey( size_t _idx ) {
    if ( _idx >= keys.size() || keys.size() != 2 )
        throw ThresholdUtils::IncorrectInput(
            "Key index is greater than number of the keys in ciphertext" );
    keys.erase( keys.begin() + ( keys.size() - _idx - 1 ) );
}

const CipheredKey& Ciphertext::getTargetKey() const {
    if ( keys.size() != 1 )
        throw ThresholdUtils::IncorrectInput( "Cannot choose a target key" );
    return keys.front();
}

}  // namespace libBLS
