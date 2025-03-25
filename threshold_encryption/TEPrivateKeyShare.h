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

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEDecryptionShare.h>
#include <threshold_encryption/TEPublicKey.h>
#include <threshold_encryption/threshold_encryption.h>

namespace libBLS {

class TEPrivateKeyShare : public TEBase {
private:
    libff::alt_bn128_Fr privateKey;

    size_t signerIndex;

public:
    TEPrivateKeyShare( std::shared_ptr< std::string > _keyStrPtr, size_t _signerIndex,
        size_t _requiredSigners, size_t _totalSigners );

    TEPrivateKeyShare( libff::alt_bn128_Fr _skeyShare, size_t _signerIndex, size_t _requiredSigners,
        size_t _totalSigners );

    static std::pair< std::shared_ptr< std::vector< std::shared_ptr< TEPrivateKeyShare > > >,
        std::shared_ptr< TEPublicKey > >
    generateSampleKeys( size_t _requiredSigners, size_t _totalSigners );

    std::string toString() const;
    std::string toStringHex() const;

    size_t getSignerIndex() const;

    libff::alt_bn128_Fr getPrivateKeyRaw() const;
};

}  // namespace libBLS

#endif  // LIBBLS_TEPRIVATEKEYSHARE_H
