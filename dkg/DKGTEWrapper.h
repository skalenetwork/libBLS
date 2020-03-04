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


#ifndef LIBBLS_DKGTEWRAPPER_H
#define LIBBLS_DKGTEWRAPPER_H

#include <dkg/DKGTESecret.h>
#include <dkg/dkg_te.h>
#include <threshold_encryption/TEPrivateKeyShare.h>

class DKGTEWrapper {
private:
    size_t requiredSigners;
    size_t totalSigners;

    std::shared_ptr< DKGTESecret > dkg_secret_ptr = NULL;

public:
    DKGTEWrapper( size_t _requiredSigners, size_t _totalSigners );

    bool VerifyDKGShare( size_t signerIndex, const encryption::element_wrapper& share,
        const std::shared_ptr< std::vector< encryption::element_wrapper > >& verification_vector );

    void setDKGSecret( std::shared_ptr< std::vector< encryption::element_wrapper > >& _poly_ptr );

    std::shared_ptr< std::vector< encryption::element_wrapper > > createDKGSecretShares();

    std::shared_ptr< std::vector< encryption::element_wrapper > > createDKGPublicShares();

    TEPrivateKeyShare CreateTEPrivateKeyShare( size_t signerIndex_,
        std::shared_ptr< std::vector< encryption::element_wrapper > > secret_shares_ptr );

    static TEPublicKey CreateTEPublicKey(
        std::shared_ptr< std::vector< std::vector< encryption::element_wrapper > > >
            public_shares_all,
        size_t _requiredSigners, size_t _totalSigners );
};


#endif  // LIBBLS_DKGTEWRAPPER_H
