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

#ifndef LIBBLS_TEPRIVATEKEYSHARE_H
#define LIBBLS_TEPRIVATEKEYSHARE_H

#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/threshold_encryption.h>

class TEPrivateKeyShare {
private:
    libff::alt_bn128_Fr privateKey;

    size_t signerIndex;
    size_t requiredSigners;
    size_t totalSigners;

public:
    TEPrivateKeyShare( std::shared_ptr< std::string > _key_str_ptr, size_t _signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    TEPrivateKeyShare( libff::alt_bn128_Fr _skey_share, size_t _signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    libff::alt_bn128_G2 getDecryptionShare( crypto::Ciphertext& cipher );

    static std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
        std::shared_ptr< TEPublicKey > >
    generateSampleKeys( size_t _requiredSigners, size_t _totalSigners );

    std::string toString() const;

    size_t getSignerIndex() const;

    libff::alt_bn128_Fr getPrivateKey() const;
};


#endif  // LIBBLS_TEPRIVATEKEYSHARE_H
