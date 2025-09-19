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

  @file BLSSignature.h
  @author Stan Kladko, Sveta Rogova
  @date 2019
*/

#ifndef LIBBLS_BLSSIGNATURE_H
#define LIBBLS_BLSSIGNATURE_H

#include <bls/bls.h>

namespace libBLS {

class BLSSignature {
private:
    algebra::G1Point sig;
    std::string hint;

    size_t requiredSigners;
    size_t totalSigners;

public:
    BLSSignature( const std::string& s, size_t _requiredSigners, size_t _totalSigners );
    BLSSignature( const algebra::G1Point& sig, const std::string& _hint,
        size_t _requiredSigners, size_t _totalSigners );
    const algebra::G1Point& getSig() const;
    std::string toString();

    std::string getHint() const;
    size_t getTotalSigners() const;
    size_t getRequiredSigners() const;

    /**
     * @brief Converts the signature share to a seed value.
     * This can be used for generating randomness based on the signature share.
     * @return A 64-bit unsigned integer seed derived from the signature share.
     */
    uint64_t toSeed();
};

}  // namespace libBLS

#endif  // LIBBLS_BLSSIGNATURE_H
