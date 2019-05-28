/*
    Copyright (C) 2018-2019 SKALE Labs

    This file is part of libBLS.

    libBLS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libBLS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libBLS.  If not, see <http://www.gnu.org/licenses/>.

    @file threshold_encryption.h
    @author Oleh Nikolaiev
    @date 2018
*/

#pragma once

#include <string>
#include <tuple>
#include <vector>
#include <utility>

#include <third_party/cryptlite/sha256.h>

#include "pbc/pbc.h"

namespace encryption{
  typedef std::tuple<element_t, std::string, element_t> Ciphertext;

  class TE{
   public:
      pairing_t pairing_;

      TE(const size_t t, const size_t n);

      ~TE();

      Ciphertext Encrypt(const std::string& message, const element_t& public_key);

      void Decrypt(element_t ret_val, const Ciphertext& ciphertext);

      void Hash(element_t ret_val, const element_t& U, const std::string& V,
                          std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

      void Hash(element_t ret_val, const element_t& Y, std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

      bool Verify(const Ciphertext& ciphertext, const element_t& decrypted, const element_t& public_key);

      std::string CombineShares(const Ciphertext& ciphertext,
                      const std::vector<std::pair<element_t, size_t>>& decrypted);

      std::vector<element_t> LagrangeCoeffs(const std::vector<int>& idx);

   private:
      const size_t t_ = 0;

      const size_t n_ = 0;
  };
}  // namespace encryption
