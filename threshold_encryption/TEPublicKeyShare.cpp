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
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    if ( !_key_str_ptr ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "public key share is null" );
    }

    // assume only using affine coordinates
    if ( _key_str_ptr->size() != 4 ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "wrong number of components in public key share" );
    }

    if ( !libBLS::ThresholdUtils::isStringNumber( _key_str_ptr->at( 0 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _key_str_ptr->at( 1 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _key_str_ptr->at( 2 ) ) ||
         !libBLS::ThresholdUtils::isStringNumber( _key_str_ptr->at( 3 ) ) ) {
        throw libBLS::ThresholdUtils::IncorrectInput(
            "non-digit symbol or first zero in non-zero public key share" );
    }

    publicKey.Z = libff::alt_bn128_Fq2::one();
    publicKey.X.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 0 ).c_str() );
    publicKey.X.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 1 ).c_str() );
    publicKey.Y.c0 = libff::alt_bn128_Fq( _key_str_ptr->at( 2 ).c_str() );
    publicKey.Y.c1 = libff::alt_bn128_Fq( _key_str_ptr->at( 3 ).c_str() );

    if ( publicKey.is_zero() || !publicKey.is_well_formed() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed(
            "corrupted string or zero public key share" );
    }
}

TEPublicKeyShare::TEPublicKeyShare(
    TEPrivateKeyShare _p_key, size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ) {
    publicKey = _p_key.getPrivateKeyRaw() * libff::alt_bn128_G2::one();
    signerIndex = _p_key.getSignerIndex();
}

bool TEPublicKeyShare::Verify(
    const libBLS::CipheredKey& cyphertext, const TEDecryptionShare& decryptionShare ) {
    libBLS::TE::checkCypher( cyphertext );
    if ( !decryptionShare.validate() ) {
        throw libBLS::ThresholdUtils::IsNotWellFormed( "Invalid decryption share" );
    }

    libBLS::TE te( *this );

    return te.Verify( cyphertext, decryptionShare.getShareRaw(), publicKey );
}

std::shared_ptr< std::vector< std::string > > TEPublicKeyShare::toString() {
    return std::make_shared< std::vector< std::string > >(
        libBLS::ThresholdUtils::G2ToString( publicKey ) );
}

libff::alt_bn128_G2 TEPublicKeyShare::getPublicKeyRaw() const {
    return publicKey;
}