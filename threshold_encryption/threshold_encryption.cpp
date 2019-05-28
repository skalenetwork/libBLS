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

#include <string.h>

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

  void TE::Hash(element_t ret_val, const element_t& Y, std::string (*hash_func)(const std::string& str)) {
    mpz_t z;
    element_to_mpz(z, Y);

    char* tmp = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    const std::string sha256hex = hash_func(tmp);

    const char* hash = sha256hex.c_str();

    mpz_t res;
    mpz_set_str(res, hash, 16);

    element_set_mpz(ret_val, res);

    mpz_clear(res);
  }

  void TE::Hash(element_t ret_val, const element_t& U, const std::string& V,
                          std::string (*hash_func)(const std::string& str)) {
    mpz_t z;
    element_to_mpz(z, U);

    char* tmp = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    const std::string sha256hex1 = hash_func(tmp);

    const char* hash1 = sha256hex1.c_str();

    const std::string sha256hex2 = hash_func(V.c_str());

    const char* hash2 = sha256hex2.c_str();

    char* hash;
    hash = malloc(strlen(hash1) + strlen(hash2));
    strcpy(hash, hash1);
    strcat(hash, hash2);

    mpz_t res;
    mpz_set_str(res, hash, 16);

    element_set_mpz(ret_val, res);

    mpz_clear(res);
  }

  bool TE::Verify(const Ciphertext& ciphertext, const element_t& decrypted, const element_t& public_key) {
    element_t U;
    element_init_G1(U, this->pairing_);
    element_set(U, std::get<0>(ciphertext));

    std::string V = std::get<1>(ciphertext);

    element_t W;
    element_init_G1(W, this->pairing_);
    element_set(W, std::get<2>(ciphertext));

    element_t H;
    element_init_G1(H, this->pairing_);
    this->Hash(H, U, V);

    element_t fst, snd;
    element_init_GT(fst, this->pairing_);
    element_init_GT(snd, this->pairing_);

    element_t g;
    element_init_G1(g, this->pairing_);
    element_set1(g);

    pairing_apply(fst, g, W, this->pairing_);
    pairing_apply(snd, U, H, this->pairing_);

    bool res = !element_cmp(fst, snd);

    bool ret_val = true;

    if (res) {
      if (element_is0(decrypted)) {
        ret_val = false;
      } else {
        element_t pp1. pp2;
        element_init_GT(pp1, this->pairing_);
        element_init_GT(pp2, this->pairing_);

        pairing_apply(pp1, decrypted, g, this->pairing_);
        pairing_apply(pp2, U, public_key, this->pairing_);

        bool check = element_cmp(pp1, pp2);
        if (check) {
          ret_val = false;
        }
      }
    }

    element_clear(U);
    element_clear(W);
    element_clear(H);

    return ret_val;
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
