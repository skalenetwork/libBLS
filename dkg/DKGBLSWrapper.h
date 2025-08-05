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

#ifndef LIBBLS_DKGBLSWRAPPER_H
#define LIBBLS_DKGBLSWRAPPER_H

#include <bls/BLSPrivateKeyShare.h>
#include <dkg/DKGBLSSecret.h>


class DKGBLSWrapper {
private:
    size_t requiredSigners;
    size_t totalSigners;

    std::shared_ptr< DKGBLSSecret > dkg_secret_ptr = NULL;

public:
    DKGBLSWrapper( size_t _requiredSigners, size_t _totalSigners );

    bool VerifyDKGShare( size_t signerIndex, const algebra::FrScalar& share,
        std::shared_ptr< std::vector< algebra::G2Point > > _verification_vector );

    void setDKGSecret( std::shared_ptr< std::vector< algebra::FrScalar > > _poly_ptr );

    std::shared_ptr< std::vector< algebra::FrScalar > > createDKGSecretShares();

    std::shared_ptr< std::vector< algebra::G2Point > > createDKGPublicShares();

    BLSPrivateKeyShare CreateBLSPrivateKeyShare(
        std::shared_ptr< std::vector< algebra::FrScalar > > secret_shares_ptr );

    algebra::FrScalar getValueAt0();

    static BLSPublicKey CreateTEPublicKey(
        std::shared_ptr< std::vector< std::vector< algebra::G2Point > > > public_shares_all,
        size_t _requiredSigners, size_t _totalSigners );
};


#endif  // LIBBLS_DKGBLSWRAPPER_H
