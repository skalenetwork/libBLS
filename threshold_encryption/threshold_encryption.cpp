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
    @date 2019
*/
#include <iostream>
#include <string.h>
#include <valarray>

#include <threshold_encryption.h>

namespace encryption {

  TE::TE(const size_t t, const size_t n) : t_(t), n_(n) {
    pairing_init_set_str(this->pairing_, aparam);

    element_init_G1(this->generator_, this->pairing_);
    
    element_random(this->generator_);
    while (element_is0(this->generator_)) {
      element_random(this->generator_);
    }
  }

  TE::~TE() {
    element_clear(this->generator_);
    pairing_clear(this->pairing_);
  }

  std::string TE::Hash(const element_t& Y, std::string (*hash_func)(const std::string& str)) {
    // assumed that Y lies in from G1

    mpz_t z;
    mpz_init(z);
    element_to_mpz(z, element_item(const_cast<element_t&>(Y), 0));

    std::string tmp1 = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    mpz_init(z);
    element_to_mpz(z, element_item(const_cast<element_t&>(Y), 1));

    std::string tmp2 = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    std::string tmp = tmp1 + tmp2;

    const std::string sha256hex = hash_func(tmp);

    const char* hash = sha256hex.c_str();

    return std::string(hash);
  }

  void TE::Hash(element_t ret_val, const element_t& U, const std::string& V,
                          std::string (*hash_func)(const std::string& str)) {
    // assumed that U lies in G1

    mpz_t z;
    mpz_init(z);
    element_to_mpz(z, element_item(const_cast<element_t&>(U), 0));

    std::string tmp1 = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    mpz_init(z);
    element_to_mpz(z, element_item(const_cast<element_t&>(U), 1));

    std::string tmp2 = mpz_get_str(NULL, 10, z);
    mpz_clear(z);

    std::string tmp = tmp1 + tmp2;

    const std::string sha256hex1 = hash_func(tmp);

    const std::string sha256hex2 = hash_func(V.c_str());

    const std::string hash = sha256hex1 + sha256hex2;

    mpz_t res;
    mpz_init(res);
    mpz_set_str(res, hash.c_str(), 16);

    element_set_mpz(ret_val, res);

    mpz_clear(res);
  }

  Ciphertext TE::Encrypt(const std::string& message, const element_t& common_public) {
    element_t r;
    element_init_Zr(r, this->pairing_);
    element_random(r);

    while (element_is0(r)) {
      element_random(r);
    }

    element_t g;
    element_init_G1(g, this->pairing_);
    element_set(g, this->generator_);

    element_t U, Y;
    element_init_G1(U, this->pairing_);
    element_init_G1(Y, this->pairing_);
    element_mul_zn(U, g, r);
    element_mul_zn(Y, const_cast<element_t&>(common_public), r);


    std::string hash = this->Hash(Y);

    // assuming message and hash are the same size strings
    // the behaviour is undefined when the two arguments are valarrays with different sizes

    std::valarray<uint8_t> lhs_to_hash(hash.size());
    for (size_t i = 0; i < hash.size(); ++i) {
      lhs_to_hash[i] = static_cast<uint8_t>(hash[i]);
    }

    std::valarray<uint8_t> rhs_to_hash(message.size());
    for (size_t i = 0; i < message.size(); ++i) {
      rhs_to_hash[i] = static_cast<uint8_t>(message[i]);
    }


    std::valarray<uint8_t> res = lhs_to_hash ^ rhs_to_hash;

    std::string V = "";
    for (size_t i = 0; i < res.size(); ++i) {
      V += static_cast<char>(res[i]);
    }

    element_t W, H;
    element_init_G1(W, this->pairing_);
    element_init_G1(H, this->pairing_);

    this->Hash(H, U, V);
    element_mul_zn(W, H, r);

    std::tuple<element_wrapper, std::string, element_wrapper> result;
    std::get<0>(result) = element_wrapper(U);
    std::get<1>(result) = V;
    std::get<2>(result) = element_wrapper(W);

    return result;
  }

  void TE::Decrypt(element_t ret_val, const Ciphertext& ciphertext, const element_t& secret_key) {
    element_t U;
    element_init_G1(U, this->pairing_);
    element_set(U, const_cast<element_t&>(std::get<0>(ciphertext).el_));

    std::string V = std::get<1>(ciphertext);

    element_t W;
    element_init_G1(W, this->pairing_);
    element_set(W, const_cast<element_t&>(std::get<2>(ciphertext).el_));

    element_t H;
    element_init_G1(H, this->pairing_);
    element_init_G1(H, this->pairing_);
    this->Hash(H, U, V);

    element_t fst, snd;
    element_init_GT(fst, this->pairing_);
    element_init_GT(snd, this->pairing_);

    element_t g;
    element_init_G1(g, this->pairing_);
    element_set(g, this->generator_);

    pairing_apply(fst, g, W, this->pairing_);
    pairing_apply(snd, U, H, this->pairing_);

    bool res = element_cmp(fst, snd);

    if (res) {
      throw std::runtime_error("cannot decrypt data");
    }

    element_mul_zn(ret_val, U, const_cast<element_t&>(secret_key));

    element_clear(g);
    element_clear(fst);
    element_clear(snd);

    element_clear(U);
    element_clear(W);
    element_clear(H);
  }

  bool TE::Verify(const Ciphertext& ciphertext, const element_t& decrypted, const element_t& public_key) {
    element_t U;
    element_init_G1(U, this->pairing_);
    element_set(U, const_cast<element_t&>(std::get<0>(ciphertext).el_));

    std::string V = std::get<1>(ciphertext);

    element_t W;
    element_init_G1(W, this->pairing_);
    element_set(W, const_cast<element_t&>(std::get<2>(ciphertext).el_));

    element_t H;
    element_init_G1(H, this->pairing_);
    this->Hash(H, U, V);

    element_t fst, snd;
    element_init_GT(fst, this->pairing_);
    element_init_GT(snd, this->pairing_);

    pairing_apply(fst, this->generator_, W, this->pairing_);
    pairing_apply(snd, U, H, this->pairing_);

    bool res = !element_cmp(fst, snd);

    bool ret_val = true;

    if (res) {
      if (element_is0(const_cast<element_t&>(decrypted))) {
        ret_val = false;
      } else {
        element_t pp1, pp2;
        element_init_GT(pp1, this->pairing_);
        element_init_GT(pp2, this->pairing_);

        pairing_apply(pp1, this->generator_, const_cast<element_t&>(decrypted), this->pairing_);
        pairing_apply(pp2, U, const_cast<element_t&>(public_key), this->pairing_);

        bool check = element_cmp(pp1, pp2);
        if (check) {
          ret_val = false;
        }

        element_clear(pp1);
        element_clear(pp2);
      }
    } else {
      ret_val = false;
    }

    element_clear(fst);
    element_clear(snd);

    element_clear(U);
    element_clear(W);
    element_clear(H);

    return ret_val;
  }

  std::string TE::CombineShares(const Ciphertext& ciphertext,
                                const std::vector<std::pair<element_wrapper, size_t>>& decrypted) {
    element_t U;
    element_init_G1(U, this->pairing_);
    element_set(U, const_cast<element_t&>(std::get<0>(ciphertext).el_));

    std::string V = std::get<1>(ciphertext);

    element_t W;
    element_init_G1(W, this->pairing_);
    element_set(W, const_cast<element_t&>(std::get<2>(ciphertext).el_));

    element_t H;
    element_init_G1(H, this->pairing_);
    this->Hash(H, U, V);

    element_t fst, snd;
    element_init_GT(fst, this->pairing_);
    element_init_GT(snd, this->pairing_);

    pairing_apply(fst, this->generator_, W, this->pairing_);
    pairing_apply(snd, U, H, this->pairing_);

    bool res = element_cmp(fst, snd);

    if (res) {
      throw std::runtime_error("error during share combinig");
    }

    std::vector<int> idx(this->t_);
    for (size_t i = 0; i < this->t_; ++i) {
      idx[i] = decrypted[i].second;
    }


    std::vector<element_wrapper> lagrange_coeffs = this->LagrangeCoeffs(idx);

    element_t sum;
    element_init_G1(sum, this->pairing_);
    element_set0(sum);
    for (size_t i = 0; i < this->t_; ++i) {
      element_t temp;
      element_init_G1(temp, this->pairing_);
      element_mul_zn(temp, (const_cast<std::vector<std::pair<element_wrapper, size_t>>&>(decrypted))[i].first.el_, lagrange_coeffs[i].el_);

      element_t tmp1;
      element_init_G1(tmp1, this->pairing_);

      element_add(tmp1, sum, temp);

      element_clear(sum);
      element_init_G1(sum, this->pairing_);
      element_set(sum, tmp1);

      element_clear(temp);
      element_clear(tmp1);
    }

    std::string hash = this->Hash(sum);

    std::valarray<uint8_t> lhs_to_hash(hash.size());
    for (size_t i = 0; i < hash.size(); ++i) {
      lhs_to_hash[i] = static_cast<uint8_t>(hash[i]);
    }

    std::valarray<uint8_t> rhs_to_hash(V.size());
    for (size_t i = 0; i < V.size(); ++i) {
      rhs_to_hash[i] = static_cast<uint8_t>(V[i]);
    }

    std::valarray<uint8_t> xor_res = lhs_to_hash ^ rhs_to_hash;

    std::string message = "";
    for (size_t i = 0; i < xor_res.size(); ++i) {
      message += static_cast<char>(xor_res[i]);
    }

    element_clear(sum);

    element_clear(fst);
    element_clear(snd);

    element_clear(U);
    element_clear(W);
    element_clear(H);

    return message;
  }

  std::vector<element_wrapper> TE::LagrangeCoeffs(const std::vector<int>& idx) {
    if (idx.size() < this->t_) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    std::vector<element_wrapper> res(this->t_);

    element_t w;
    element_init_Zr(w, this->pairing_);
    element_set1(w);

    element_t a;
    element_init_Zr(a, this->pairing_);

    for (size_t i = 0; i < this->t_; ++i) {
      element_mul_si(a, w, idx[i]);
      element_clear(w);
      element_init_Zr(w, this->pairing_);
      element_set(w, a);
    }

    element_clear(a);

    for (size_t i = 0; i < this->t_; ++i) {
      element_t v;
      element_init_Zr(v, this->pairing_);
      element_set_si(v, idx[i]);

      for (size_t j = 0; j < this->t_; ++j) {
        if (j != i) {
          if (idx[i] == idx[j]) {
            throw std::runtime_error("Error during the interpolation, have same indexes in the list of indexes");
          }

          element_t u;
          element_init_Zr(u, this->pairing_);

          element_set_si(u, idx[j] - idx[i]);

          element_init_Zr(a, this->pairing_);
          element_mul_zn(a, v, u);
          element_clear(v);
          element_init_Zr(v, this->pairing_);
          element_set(v, a);

          element_clear(a);

          element_clear(u);
        }
      }

      element_init_Zr(a, this->pairing_);
      element_invert(a, v);
      element_clear(v);
      element_init_Zr(v, this->pairing_);
      element_set(v, a);

      element_clear(a);


      element_init_Zr(a, this->pairing_);
      element_mul_zn(a, w, v);

      element_init_Zr(res[i].el_, this->pairing_);
      element_set(res[i].el_, a);

      element_clear(a);

      element_clear(v);
    }

    element_clear(w);

    return res;
  }

}  // namespace encrtyption
