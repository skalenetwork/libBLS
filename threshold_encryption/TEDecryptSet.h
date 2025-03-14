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

#include <threshold_encryption/TEBase.h>
#include <threshold_encryption/TEDecryptionShare.h>
#include <threshold_encryption/threshold_encryption.h>
#include <unordered_set>

/**
 * @brief A class to manage threshold encryption's decryption sets
 *
 * TEDecryptSet handles partial decryption shares from multiple signers in a threshold encryption
 * scheme. It collects and combines these shares to reconstruct the original encrypted message.
 *
 *
 * @details The class maintains a collection of partial decrypts from different participants and
 * keeps track of merging status on this set of decryption shares.
 */
class TEDecryptSet : public TEBase {
public:
    enum class MergeStatus {
        NOT_ENOUGH_SHARES,
        READY_TO_MERGE,
        ALREADY_MERGED,
    };

private:
    MergeStatus mergeStatus = MergeStatus::NOT_ENOUGH_SHARES;

    std::unordered_set< TEDecryptionShare, TEDecryptionShareHash > decrypts;

public:
    TEDecryptSet( size_t _requiredSigners, size_t _totalSigners );

    void addDecryptShare( TEDecryptionShare _share );

    size_t size() const;

    bool canMerge() const;

    void markAsMerged();

    MergeStatus getMergeStatus() const;

    std::vector< std::pair< libff::alt_bn128_G2, size_t > > getSharesRaw() const;
};


#endif  // LIBBLS_TEDECRYPTSET_H
