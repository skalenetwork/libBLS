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

  @file TEPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_TEDECRYPTSET_H
#define LIBBLS_TEDECRYPTSET_H

#include <threshold_encryption/threshold_encryption.h>
#include <map>

class TEDecryptSet {
private:
    size_t requiredSigners;
    size_t totalSigners;

    bool was_merged;

    std::map< size_t, std::shared_ptr< encryption::element_wrapper > > decrypts;

public:
    TEDecryptSet( size_t _requiredSigners, size_t _totalSigners );

    void addDecrypt( size_t _signerIndex, std::shared_ptr< encryption::element_wrapper > _el );

    std::string merge( const encryption::Ciphertext& ciphertext );
};


#endif  // LIBBLS_TEDECRYPTSET_H
