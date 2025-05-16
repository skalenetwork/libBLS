/*
Copyright (C) 2018-2019 SKALE Labs

This file is part of libBLS.

libBLS is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

libBLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with libBLS. If not, see <https://www.gnu.org/licenses/>.

@file TECiphertext.cpp
@author Sidnei Teixeira
@date 2025
*/

#include <threshold_encryption/TECiphertext.h>

namespace libBLS {

/// ---------------------------------------------------------------
///                         CipheredKey
/// ---------------------------------------------------------------

std::array< uint8_t, CipheredKey::SIZE_BYTES > CipheredKey::toBytes() const {
    std::array< uint8_t, SIZE_BYTES > bytes;
    uint8_t* source = bytes.data();
    // set U component
    auto u_bytes = ThresholdUtils::G2ToBytes( U );
    std::memcpy( source, u_bytes.data(), u_bytes.size() );
    source += u_bytes.size();
    // set V commponent
    std::memcpy( source, V.data(), V.size() );
    source += V.size();
    // set W component
    auto w_bytes = ThresholdUtils::G1ToBytes( W );
    std::memcpy( source, w_bytes.data(), w_bytes.size() );

    return bytes;
}
    

CipheredKey CipheredKey::fromBytes( std::array< uint8_t, SIZE_BYTES > bytes ) {
    std::array< uint8_t, G2_SIZE_BYTES > u_bytes;
    std::array< uint8_t, AES_256_KEY_SIZE_BYTES > v_bytes;
    std::array< uint8_t, G1_SIZE_BYTES > w_bytes;

    uint8_t* offset = bytes.data();
    // Get U bytes
    std::memcpy( u_bytes.data(), offset, G2_SIZE_BYTES );
    offset += G2_SIZE_BYTES;
    // Get V bytes
    std::memcpy( v_bytes.data(), offset, AES_256_KEY_SIZE_BYTES );
    offset += AES_256_KEY_SIZE_BYTES;
    // Get W bytes
    std::memcpy( w_bytes.data(), offset, G1_SIZE_BYTES );

    // Convert to CipheredKey components
    libff::alt_bn128_G2 U = ThresholdUtils::bytesToG2( u_bytes );
    libff::alt_bn128_G1 W = ThresholdUtils::bytesToG1( w_bytes );

    // constructor performs validation
    return CipheredKey( U, v_bytes, W );
}
    

void CipheredKey::validate() const {
    ThresholdUtils::validateG1( W );
    ThresholdUtils::validateG2( U );
}
    
CipheredKey CipheredKey::random() {
    libff::alt_bn128_G2 U = libff::alt_bn128_G2::random_element();
    AES256Key V;
    RAND_bytes( V.data(), V.size() );
    libff::alt_bn128_G1 W = libff::alt_bn128_G1::random_element();
    return CipheredKey( U, V, W );
}
    

/// ---------------------------------------------------------------
///                         Ciphertext
/// ---------------------------------------------------------------

std::string Ciphertext::getPublicDecryptionValue() {
    auto U = key.U;
    U.to_affine_coordinates();

    // validate U
    ThresholdUtils::validateG2( U );

    auto u_splitted = ThresholdUtils::G2ToString( U, BASE_HEXA );

    // convert to string
    std::string public_decryption_value;
    for ( size_t j = 0; j < u_splitted.size(); ++j ) {
        public_decryption_value += u_splitted[j];
    }

    return public_decryption_value;
}
    
    
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
    // get key bytes
    std::array< uint8_t, CipheredKey::SIZE_BYTES > keyBytes = key.toBytes();
    // preallocate vec
    std::vector< uint8_t > bytes( CipheredKey::SIZE_BYTES + data->size() );
    // Copy keyBytes into the first part of bytes
    std::copy( keyBytes.begin(), keyBytes.end(), bytes.begin() );
    // Copy data bytes after keyBytes
    std::copy( data->begin(), data->end(), bytes.begin() + keyBytes.size() );

    return bytes;
}
    

Ciphertext Ciphertext::fromBytes( std::vector< uint8_t >& bytes ) {
    // we require at least key size + random secret size + 1 byte for data field
    if ( bytes.size() <= CipheredKey::SIZE_BYTES + RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IncorrectInput( "Cyphertext data is too short" );
    }

    // get key bytes
    std::array< uint8_t, CipheredKey::SIZE_BYTES > keyBytes;
    std::copy(
        bytes.begin(), bytes.begin() + CipheredKey::SIZE_BYTES, keyBytes.begin() );
    // get data bytes
    std::vector< uint8_t > data(
        bytes.begin() + CipheredKey::SIZE_BYTES, bytes.end() );

    // get key structure
    CipheredKey key = CipheredKey::fromBytes( keyBytes );

    return Ciphertext( key, data );
}
    

void Ciphertext::validate() const {
    key.validate();

    if ( !data ) {
        throw ThresholdUtils::IsNotWellFormed( "Cyphertext data is not initialized" );
    }

    // actual data without random secret must be at least 1 byte long
    if ( data->size() <= RANDOM_SECRET_SIZE_BYTES ) {
        throw ThresholdUtils::IsNotWellFormed(
            "Cyphertext data is too short to hold random secret and at least 1 byte of data." );
    }
}

}