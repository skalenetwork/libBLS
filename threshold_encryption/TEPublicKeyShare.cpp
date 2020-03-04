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
along with libBLS.  If not, see <https://www.gnu.org/licenses/>.

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/

#include <TEDataSingleton.h>
#include <threshold_encryption/TEPublicKeyShare.h>
#include <threshold_encryption/utils.h>

TEPublicKeyShare::TEPublicKeyShare( std::shared_ptr< std::vector< std::string > > _key_str_ptr,
    size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str_ptr ) {
        throw std::runtime_error( "public key share is null" );
    }

    if ( _key_str_ptr->size() != 2 )
        throw std::runtime_error( "wrong number of components in public key share" );

    if ( !isStringNumber( _key_str_ptr->at( 0 ) ) || !isStringNumber( _key_str_ptr->at( 1 ) ) )
        throw std::runtime_error( "non-digit symbol or first zero in non-zero public key share" );

    std::string key_str = "[" + _key_str_ptr->at( 0 ) + "," + _key_str_ptr->at( 1 ) + "]";

    element_t pkey;
    element_init_G1( pkey, TEDataSingleton::getData().pairing_ );
    element_set_str( pkey, key_str.c_str(), 10 );
    PublicKey = encryption::element_wrapper( pkey );
    element_clear( pkey );

    if ( isG1Element0( PublicKey.el_ ) ) {
        throw std::runtime_error( "corrupted string or zero public key share" );
    }
}

TEPublicKeyShare::TEPublicKeyShare(
    TEPrivateKeyShare _p_key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    element_t pkey;
    element_init_G1( pkey, TEDataSingleton::getData().pairing_ );
    element_mul_zn( pkey, TEDataSingleton::getData().generator_, _p_key.getPrivateKey().el_ );

    PublicKey = pkey;
    signerIndex = _p_key.getSignerIndex();
    element_clear( pkey );
}

bool TEPublicKeyShare::Verify(
    const encryption::Ciphertext& cyphertext, const element_t& decrypted ) {
    checkCypher( cyphertext );
    if ( isG1Element0( const_cast< element_t& >( decrypted ) ) ) {
        throw std::runtime_error( "zero decrypt" );
    }

    encryption::TE te( requiredSigners, totalSigners );

    return te.Verify( cyphertext, decrypted, PublicKey.el_ );
}

std::shared_ptr< std::vector< std::string > > TEPublicKeyShare::toString() {
    return ElementG1ToString( PublicKey.el_ );
}

encryption::element_wrapper TEPublicKeyShare::getPublicKey() const {
    return PublicKey;
}
