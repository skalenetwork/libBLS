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

  @file TEPrivateKeyShare.h
  @author Sveta Rogova
  @date 2019
*/


#include "DKGTESecret.h"

#include <dkg/dkg_te.h>
#include <threshold_encryption/TEDataSingleton.h>

DKGTESecret::DKGTESecret( size_t _requiredSigners, size_t _totalSigners )
    : requiredSigners( _requiredSigners ), totalSigners( _totalSigners ) {
    TEDataSingleton::checkSigners( _requiredSigners, _totalSigners );

    encryption::DkgTe dkg_te( requiredSigners, totalSigners );
    poly = dkg_te.GeneratePolynomial();
}

void DKGTESecret::setPoly( std::vector< encryption::element_wrapper >& _poly ) {
    if ( _poly.size() != requiredSigners ) {
        throw std::runtime_error( "Wrong size of vector" );
    }

    poly = _poly;
}

std::vector< encryption::element_wrapper > DKGTESecret::getDKGTESecretShares() {
    encryption::DkgTe dkg_te( requiredSigners, totalSigners );
    return dkg_te.CreateSecretKeyContribution( poly );
}

std::vector< encryption::element_wrapper > DKGTESecret::getDKGTEPublicShares() {
    encryption::DkgTe dkg_te( requiredSigners, totalSigners );
    return dkg_te.CreateVerificationVector( poly );
}
