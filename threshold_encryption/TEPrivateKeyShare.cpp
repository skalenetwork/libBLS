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

namespace libBLS {

TEPrivateKeyShare::TEPrivateKeyShare( std::shared_ptr< std::string > _keyStrPtr,
    size_t _signerIndex, size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ), signerIndex( _signerIndex ) {
    if ( !_keyStrPtr ) {
        throw ThresholdUtils::IncorrectInput( "private key share is null" );
    }

    privateKey = libff::alt_bn128_Fr( _keyStrPtr->c_str() );

    if ( privateKey.is_zero() ) {
        throw ThresholdUtils::ZeroSecretKey( "Zero private key share" );
    }
}

TEPrivateKeyShare::TEPrivateKeyShare( libff::alt_bn128_Fr _skeyShare, size_t _signerIndex,
    size_t _requiredSigners, size_t _totalSigners )
    : TEBase( _requiredSigners, _totalSigners ),
      privateKey( _skeyShare ),
      signerIndex( _signerIndex ) {
    if ( _signerIndex > _totalSigners ) {
        throw ThresholdUtils::IncorrectInput( "Wrong _signerIndex" );
    }

    if ( _skeyShare.is_zero() ) {
        throw ThresholdUtils::ZeroSecretKey( "Zero private key share" );
    }
}

std::string TEPrivateKeyShare::toString() const {
    return ThresholdUtils::fieldElementToString( privateKey, BASE_DEC );
}

std::string TEPrivateKeyShare::toStringHex() const {
    return ThresholdUtils::fieldElementToString( privateKey, BASE_HEXA );
}

size_t TEPrivateKeyShare::getSignerIndex() const {
    return signerIndex;
}

libff::alt_bn128_Fr TEPrivateKeyShare::getPrivateKeyRaw() const {
    return privateKey;
}

std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
    std::shared_ptr< TEPublicKey > >
TEPrivateKeyShare::generateSampleKeys( size_t _requiredSigners, size_t _totalSigners ) {
    Dkg dkgTe( _requiredSigners, _totalSigners );

    std::vector< libff::alt_bn128_Fr > poly = dkgTe.GeneratePolynomial();

    libff::alt_bn128_Fr commonSkey = dkgTe.PolynomialValue( poly, libff::alt_bn128_Fr::zero() );
    TEPrivateKey commonPrivate( commonSkey, _requiredSigners, _totalSigners );
    TEPublicKey commonPublic( commonPrivate );

    std::vector< libff::alt_bn128_Fr > skeys = dkgTe.SecretKeyContribution( poly );

    std::vector< std::shared_ptr< TEPrivateKeyShare > > skeyShares;

    for ( size_t i = 0; i < _totalSigners; i++ ) {
        TEPrivateKeyShare skey( skeys[i], i + 1, _requiredSigners, _totalSigners );
        skeyShares.emplace_back( std::make_shared< TEPrivateKeyShare >( skey ) );
    }

    auto keys = std::make_pair(
        std::make_shared< std::vector< std::shared_ptr< TEPrivateKeyShare > > >( skeyShares ),
        std::make_shared< TEPublicKey >( commonPublic ) );
    return keys;
}

}  // namespace libBLS
