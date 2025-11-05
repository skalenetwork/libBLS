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


#include <dkg/DKGTESecret.h>
#include <tools/utils.h>

#include <dkg/dkg.h>

DKGTESecret::DKGTESecret( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    libBLS::ThresholdUtils::checkSigners( _requiredSigners, _totalSigners );

    libff::init_alt_bn128_params();

    libBLS::Dkg dkg_te( requiredSigners, totalSigners );
    poly = dkg_te.GeneratePolynomial();
}

void DKGTESecret::setPoly( std::vector< libff::alt_bn128_Fr >& _poly ) {
    if ( _poly.size() != requiredSigners ) {
        throw libBLS::ThresholdUtils::IncorrectInput( "Wrong size of vector" );
    }

    poly = _poly;
}

std::vector< libff::alt_bn128_Fr > DKGTESecret::getDKGTESecretShares() {
    libBLS::Dkg dkg_te( requiredSigners, totalSigners );
    return dkg_te.SecretKeyContribution( poly );
}

std::vector< libff::alt_bn128_G2 > DKGTESecret::getDKGTEPublicShares() {
    libBLS::Dkg dkg_te( requiredSigners, totalSigners );
    return dkg_te.VerificationVector( poly );
}
