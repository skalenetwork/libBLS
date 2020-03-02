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


#ifndef LIBBLS_DKGTESECRET_H
#define LIBBLS_DKGTESECRET_H

#include <threshold_encryption/threshold_encryption.h>

class DKGTESecret {
private:
    size_t requiredSigners;
    size_t totalSigners;
    std::vector< encryption::element_wrapper > poly;

public:
    DKGTESecret( size_t _requiredSigners, size_t _totalSigners );
    void setPoly( std::vector< encryption::element_wrapper >& _poly );
    std::vector< encryption::element_wrapper > getDKGTESecretShares();
    std::vector< encryption::element_wrapper > getDKGTEPublicShares();
};


#endif  // LIBBLS_DKGTESECRET_H
