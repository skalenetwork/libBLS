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

#include <threshold_encryption/TEDataSingleton.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/utils.h>

#include <iostream>
#include <utility>


TEPublicKey::TEPublicKey( std::shared_ptr< std::vector< std::string > > _key_str_ptr,
    size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str_ptr ) {
        throw std::runtime_error( "public key is null" );
    }

    std::string key_str = "[" + _key_str_ptr->at( 0 ) + "," + _key_str_ptr->at( 1 ) + "]";

    element_t pkey;
    element_init_G1( pkey, TEDataSingleton::getData().pairing_ );
    element_set_str( pkey, key_str.c_str(), 10 );
    PublicKey = encryption::element_wrapper( pkey );
    element_clear( pkey );

    if ( isG1Element0( PublicKey.el_ ) ) {
        throw std::runtime_error( "corrupted string or zero public key" );
    }
}

TEPublicKey::TEPublicKey(
    TEPrivateKey _comon_private, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    if ( element_is0( _comon_private.getPrivateKey().el_ ) ) {
        throw std::runtime_error( "zero key" );
    }

    element_t pkey;
    element_init_G1( pkey, TEDataSingleton::getData().pairing_ );
    element_mul_zn(
        pkey, TEDataSingleton::getData().generator_, _comon_private.getPrivateKey().el_ );

    PublicKey = pkey;
    element_clear( pkey );
}

TEPublicKey::TEPublicKey(
    encryption::element_wrapper _pkey, size_t _requiredSigners, size_t _totalSigners )
    : PublicKey( _pkey ), requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    if ( isG1Element0( _pkey.el_ ) ) {
        throw std::runtime_error( "zero public key" );
    }
}

encryption::Ciphertext TEPublicKey::encrypt( const std::shared_ptr< std::string >& mes_ptr ) {
    encryption::TE te( requiredSigners, totalSigners );

    if ( mes_ptr == nullptr ) {
        throw std::runtime_error( "Message is null" );
    }

    if ( mes_ptr->length() != 64 ) {
        throw std::runtime_error( "Message length is not equal to 64" );
    }

    encryption::Ciphertext cypher = te.Encrypt( *mes_ptr, PublicKey.el_ );
    checkCypher( cypher );

    element_t U;
    element_init_G1( U, TEDataSingleton::getData().pairing_ );
    element_set( U, std::get< 0 >( cypher ).el_ );
    encryption::element_wrapper U_wrap( U );
    /*if (element_item_count(U) == 0 ) {
      throw std::runtime_error("U is zero");
    }*/

    element_t W;
    element_init_G1( W, TEDataSingleton::getData().pairing_ );
    element_set( W, std::get< 2 >( cypher ).el_ );
    /*if (element_item_count(W) == 0) {
      throw std::runtime_error("W is zero");
    }*/
    encryption::element_wrapper W_wrap( W );
    element_clear( W );

    element_clear( U );

    return std::make_tuple( U_wrap, std::get< 1 >( cypher ), W_wrap );
}

std::shared_ptr< std::vector< std::string > > TEPublicKey::toString() {
    return ElementG1ToString( PublicKey.el_ );
}

encryption::element_wrapper TEPublicKey::getPublicKey() const {
    return PublicKey;
}
