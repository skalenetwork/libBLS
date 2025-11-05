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

  @file BLSPublicKey.h
  @author Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSPUBLICKEY_H
#define LIBBLS_BLSPUBLICKEY_H


#include <bls/BLSSignature.h>
#include <bls/bls.h>

class BLSPublicKeyShare;

class BLSPublicKey {
private:
    std::shared_ptr< libff::alt_bn128_G2 > libffPublicKey;
    size_t t;
    size_t n;

public:
    BLSPublicKey( const std::shared_ptr< std::vector< std::string > > );
    // default value set to 0 for compatibility
    BLSPublicKey( const libff::alt_bn128_Fr& skey, size_t t = 0, size_t n = 0 );
    // default value set to 0 for compatibility
    BLSPublicKey( const libff::alt_bn128_G2& skey, size_t t = 0, size_t n = 0 );

    BLSPublicKey(
        std::shared_ptr< std::map< size_t, std::shared_ptr< BLSPublicKeyShare > > > map_pkeys_koefs,
        size_t _requiredSigners, size_t _totalSigners );

    bool VerifySig( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
        std::shared_ptr< BLSSignature > sign_ptr );

    bool VerifySigWithHelper( std::shared_ptr< std::array< uint8_t, 32 > > hash_ptr,
        std::shared_ptr< BLSSignature > sign_ptr );

    bool AggregatedVerifySig(
        std::vector< std::shared_ptr< std::array< uint8_t, 32 > > >& hash_ptr_vec,
        std::vector< std::shared_ptr< BLSSignature > >& sign_ptr_vec );

    std::shared_ptr< std::vector< std::string > > toString();

    std::shared_ptr< libff::alt_bn128_G2 > getPublicKey() const;

    size_t getRequiredSigners() const { return t; }

    size_t getTotalSigners() const { return n; }
};


#endif  // LIBBLS_BLSPUBLICKEY_H
