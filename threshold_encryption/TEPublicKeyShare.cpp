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

@file TEPublicKey.h
@author Sveta Rogova
@date 2019
*/

#include <threshold_encryption/TEPublicKeyShare.h>
#include <tools/utils.h>

TEPublicKeyShare::TEPublicKeyShare( std::shared_ptr< std::vector< std::string > > _key_str_ptr,
    size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str_ptr ) {
        throw std::runtime_error( "public key share is null" );
    }

    if ( _key_str_ptr->size() != 4 ) {
        throw std::runtime_error( "wrong number of components in public key share" );
    }

    if ( !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 0 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 1 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 2 ) ) ||
         !crypto::ThresholdUtils::isStringNumber( _key_str_ptr->at( 3 ) ) ) {
        throw std::runtime_error( "non-digit symbol or first zero in non-zero public key share" );
    }

    libff::init_alt_bn128_params();

    PublicKey.Z = libff::alt_bn128_Fq2::one();
    PublicKey.X.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 0 ).c_str() );
    PublicKey.X.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 1 ).c_str() );
    PublicKey.Y.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 2 ).c_str() );
    PublicKey.Y.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 3 ).c_str() );

    if ( PublicKey.is_zero() ) {
        throw std::runtime_error( "corrupted string or zero public key share" );
    }
}

TEPublicKeyShare::TEPublicKeyShare(
    TEPrivateKeyShare _p_key, size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    PublicKey = _p_key.getPrivateKey() * libff::alt_bn128_G2::one();
    signerIndex = _p_key.getSignerIndex();
}

bool TEPublicKeyShare::Verify(
    const crypto::Ciphertext& cyphertext, const libff::alt_bn128_G2& decryptionShare ) {
    crypto::ThresholdUtils::checkCypher( cyphertext );
    if ( decryptionShare.is_zero() ) {
        throw std::runtime_error( "zero decrypt" );
    }

    crypto::TE te( requiredSigners, totalSigners );

    return te.Verify( cyphertext, decryptionShare, PublicKey );
}

std::shared_ptr< std::vector< std::string > > TEPublicKeyShare::toString() {
    return std::make_shared< std::vector< std::string > >(
        crypto::ThresholdUtils::G2ToString( PublicKey ) );
}

libff::alt_bn128_G2 TEPublicKeyShare::getPublicKey() const {
    return PublicKey;
}
