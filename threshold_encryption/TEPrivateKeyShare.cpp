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

@file TEPrivateKeyShare.h
@author Sveta Rogova
@date 2019
*/

#include <dkg/dkg.h>
#include <threshold_encryption/TEPrivateKeyShare.h>
#include <tools/utils.h>

TEPrivateKeyShare::TEPrivateKeyShare( std::shared_ptr< std::string > _key_str, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( !_key_str ) {
        throw std::runtime_error( "private key share is null" );
    }

    libff::init_alt_bn128_params();

    privateKey = libff::alt_bn128_Fr( _key_str->c_str() );

    if ( privateKey.is_zero() ) {
        throw std::runtime_error( "Zero private key share" );
    }
}

TEPrivateKeyShare::TEPrivateKeyShare( libff::alt_bn128_Fr _skey_share, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : privateKey( _skey_share ),
      signerIndex( _signerIndex ),
      requiredSigners( _requiredSigners ),
      totalSigners( _totalSigners ) {
    crypto::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    if ( _signerIndex > _totalSigners ) {
        throw std::runtime_error( "Wrong _signerIndex" );
    }

    libff::init_alt_bn128_params();

    if ( _skey_share.is_zero() ) {
        throw std::runtime_error( "Zero private key share" );
    }
}

libff::alt_bn128_G2 TEPrivateKeyShare::getDecryptionShare( crypto::Ciphertext& cipher ) {
    crypto::ThresholdUtils::checkCypher( cipher );

    crypto::TE te( requiredSigners, totalSigners );

    libff::alt_bn128_G2 decryption_share = te.getDecryptionShare( cipher, privateKey );

    if ( decryption_share.is_zero() ) {
        std::runtime_error( "zero decrypt" );
    }

    return decryption_share;
}

std::string TEPrivateKeyShare::toString() const {
    return crypto::ThresholdUtils::fieldElementToString( privateKey );
}

size_t TEPrivateKeyShare::getSignerIndex() const {
    return signerIndex;
}

libff::alt_bn128_Fr TEPrivateKeyShare::getPrivateKey() const {
    return privateKey;
}

std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
    std::shared_ptr< TEPublicKey > >
TEPrivateKeyShare::generateSampleKeys( size_t _requiredSigners, size_t _totalSigners ) {
    crypto::Dkg dkg_te( _requiredSigners, _totalSigners );

    std::vector< libff::alt_bn128_Fr > poly = dkg_te.GeneratePolynomial();

    libff::alt_bn128_Fr common_skey = dkg_te.PolynomialValue( poly, libff::alt_bn128_Fr::zero() );
    TEPrivateKey common_private( common_skey, _requiredSigners, _totalSigners );
    TEPublicKey common_public( common_private, _requiredSigners, _totalSigners );

    std::vector< libff::alt_bn128_Fr > skeys = dkg_te.SecretKeyContribution( poly );

    std::vector< std::shared_ptr< TEPrivateKeyShare > > skey_shares;

    for ( size_t i = 0; i < _totalSigners; i++ ) {
        TEPrivateKeyShare skey( skeys[i], i + 1, _requiredSigners, _totalSigners );
        skey_shares.emplace_back( std::make_shared< TEPrivateKeyShare >( skey ) );
    }

    auto keys = std::make_pair(
        std::make_shared< std::vector< std::shared_ptr< TEPrivateKeyShare > > >( skey_shares ),
        std::make_shared< TEPublicKey >( common_public ) );
    return keys;
}
