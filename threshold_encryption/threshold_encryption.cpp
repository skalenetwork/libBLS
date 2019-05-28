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

    @file threshold_encryption.cpp
    @author Oleh Nikolaiev
    @date 2018
*/

#include <threshold_encryption.h>

namespace encryption {

  static char *aparam =
      "type a\n"
      "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
      "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
      "r 730750818665451621361119245571504901405976559617\n"
      "exp2 159\n"
      "exp1 107\n"
      "sign1 1\n"
      "sign0 1\n";

  TE::TE(const size_t t, const size_t n) : t_(t), n_(n) {
    pairing_init_set_str(this->pairing_, aparam);
  }

  TE::~TE() {
    pairing_clear(this->pairing_);
  }

  bool TE::Verify(const Ciphertext& ciphertext, const element_t& decrypted) {
    return true;
  }

  std::vector<element_t> TE::LagrangeCoeffs(const std::vector<int>& idx) {
    if (idx.size() < this->t_) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    std::vector<element_t> res(this->t_);

    element_t w;
    element_set1(w);

    for (size_t i = 0; i < this->t_; ++i) {
      element_mul_si(w, w, idx[i]);
    }

    for (size_t i = 0; i < this->t_; ++i) {
      element_t v;
      element_set_si(v, idx[i]);

      for (size_t j = 0; j < this->t_; ++j) {
        if (j != i) {
          if (idx[i] == idx[j]) {
            throw std::runtime_error("Error during the interpolation, have same indexes in the list of indexes");
          }

          element_t u;
          element_init_Zr(u, this->pairing_);

          element_set_si(u, idx[j] - idx[i]);

          element_mul(v, v, u);

          element_clear(u);
        }
      }

      element_invert(v, v);

      element_mul(w, w, v);

      element_set(res[i], w);

      element_clear(v);
    }

    element_clear(w);

    return res;
  }

}  // namespace encrtyption
