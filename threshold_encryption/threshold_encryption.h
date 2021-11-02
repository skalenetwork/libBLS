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

@file threshold_encryption.h
@author Oleh Nikolaiev
@date 2019
*/

#pragma once

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <third_party/cryptlite/sha256.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

namespace libBLS {

typedef std::tuple< libff::alt_bn128_G2, std::string, libff::alt_bn128_G1 > Ciphertext;

class TE {
public:
    TE( const size_t t, const size_t n );

    ~TE();

    static Ciphertext getCiphertext(
        const std::string& message, const libff::alt_bn128_G2& common_public );

    static std::pair< Ciphertext, std::vector< uint8_t > > encryptWithAES(
        const std::string& message, const libff::alt_bn128_G2& common_public );

    static std::string encryptMessage(
        const std::string& message, const std::string& common_public );

    static libff::alt_bn128_G2 getDecryptionShare(
        const Ciphertext& ciphertext, const libff::alt_bn128_Fr& secret_key );

    static libff::alt_bn128_G1 HashToGroup( const libff::alt_bn128_G2& U, const std::string& V,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static std::string Hash( const libff::alt_bn128_G2& Y,
        std::string ( *hash_func )( const std::string& str ) = cryptlite::sha256::hash_hex );

    static bool Verify( const Ciphertext& ciphertext, const libff::alt_bn128_G2& decryptionShare,
        const libff::alt_bn128_G2& public_key );

    std::string CombineShares( const Ciphertext& ciphertext,
        const std::vector< std::pair< libff::alt_bn128_G2, size_t > >& decryptionShare );

    static void checkCypher( const Ciphertext& cypher );

    static std::string aesCiphertextToString(
        const Ciphertext& cipher, const std::vector< uint8_t >& data );

    static std::pair< Ciphertext, std::vector< uint8_t > > aesCiphertextFromString(
        const std::string& str );

    static const std::string MAGIC_STRING;

private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace libBLS
