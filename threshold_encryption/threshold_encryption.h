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
    @date 2019
*/

#pragma once

#include <string>
#include <tuple>
#include <vector>
#include <utility>

#include <third_party/cryptlite/sha256.h>

#include "pbc/pbc.h"

namespace encryption{

  static char aparam[] =
      "type a\n"
      "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
      "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
      "r 730750818665451621361119245571504901405976559617\n"
      "exp2 159\n"
      "exp1 107\n"
      "sign1 1\n"
      "sign0 1\n";

  class element_wrapper {
   public:
      element_t el_ = {0};

      void clear() {
          if (el_[0].data)
            element_clear(el_);
      }

      void assign(const element_t& e) {
          if (((void*)(&el_)) == ((void*)(&e))) {
            return;
          }

          element_init_same_as(el_, const_cast<element_t&>(e));
          element_set(el_, const_cast<element_t&>(e));
      }

      void assign(const element_wrapper& other) {
          if (((void*)this) == ((void*)(&other))) {
            return;
          }

          assign(other.el_);
      }

      element_wrapper() {}

      element_wrapper(const element_wrapper& other) {
          assign(other);
      }

      element_wrapper(const element_t& e) {
          assign(e);
      }

      ~element_wrapper() {
          clear();
      }

      element_wrapper& operator=(const element_wrapper& other) {
          assign(other);
          return (*this);
      }

      element_wrapper& operator=(const element_t& e) {
          assign(e);
          return (*this);
      }
  };

  typedef std::tuple<element_wrapper, std::string, element_wrapper> Ciphertext;

  class TE{
   public:
      pairing_t pairing_;
      
      element_t generator_ = { 0 };

      TE(const size_t t, const size_t n);

      ~TE();

      Ciphertext Encrypt(const std::string& message, const element_t& common_public);

      void Decrypt(element_t ret_val, const Ciphertext& ciphertext, const element_t& secret_key);

      void Hash(element_t ret_val, const element_t& U, const std::string& V,
                          std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

      std::string Hash(const element_t& Y, std::string (*hash_func)(const std::string& str) =
                                               cryptlite::sha256::hash_hex);

      bool Verify(const Ciphertext& ciphertext, const element_t& decrypted, const element_t& public_key);

      std::string CombineShares(const Ciphertext& ciphertext,
                                const std::vector<std::pair<element_wrapper, size_t>>& decrypted);

      std::vector<element_wrapper> LagrangeCoeffs(const std::vector<int>& idx);

   private:
      const size_t t_ = 0;

      const size_t n_ = 0;
  };
}  // namespace encryption
