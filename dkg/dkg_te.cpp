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

  @file dkg_te.cpp
  @author Oleh Nikolaiev
  @date 2019
 */

#include <dkg/dkg_te.h>

#include <iostream>

namespace encryption {

  typedef std::vector<element_wrapper> Polynomial;

  DkgTe::DkgTe(const size_t t, const size_t n) : t_(t), n_(n) {
    pairing_init_set_str(this->pairing_, aparam);

    element_init_G1(this->generator_, this->pairing_);
    
    element_random(this->generator_);
    while (element_is0(this->generator_)) {
      element_random(this->generator_);
    }
  }

  Polynomial DkgTe::GeneratePolynomial() {
    Polynomial pol(this->t_);

    for (size_t i = 0; i < this->t_; ++i) {
      element_t g;
      element_init_Zr(g, this->pairing_);
      element_random(g);
      
      while (i == this->t_ - 1 && element_is0(g)) {
        element_random(g);
      }

      pol[i] = element_wrapper(g);

      element_clear(g);
    }

    return pol;
  }

  std::vector<element_wrapper> DkgTe::CreateVerificationVector(
                                        const std::vector<element_wrapper>& polynomial) {
    std::vector<element_wrapper> verification_vector(this->t_);

    for (size_t i = 0; i < this->t_; ++i) {
      element_t tmp;
      element_init_G1(tmp, this->pairing_);
      element_mul_zn(tmp, this->generator_, const_cast<element_t&>(polynomial[i].el_));
      
      verification_vector[i] = element_wrapper(tmp);

      element_clear(tmp);
    }

    return verification_vector;
  }

  element_wrapper DkgTe::ComputePolynomialValue(const std::vector<element_wrapper>& polynomial,
                                    const element_wrapper& point) {
    element_t value;
    element_init_Zr(value, this->pairing_);
    element_set0(value);

    element_t pow;
    element_init_Zr(pow, this->pairing_);
    element_set1(pow);

    for (size_t i = 0; i < this->t_; ++i) {
      if (i == this->t_ - 1 && element_is0(const_cast<element_t&>(polynomial[i].el_))) {
        throw std::runtime_error("Error, incorrect degree of a polynomial");
      }
      element_t tmp;
      element_init_Zr(tmp, this->pairing_);
      element_mul(tmp, const_cast<element_t&>(polynomial[i].el_), pow);

      element_t tmp1;
      element_init_Zr(tmp1, this->pairing_);
      element_set(tmp1, value);

      element_add(value, tmp1, tmp);

      element_clear(tmp1);

      element_clear(tmp);

      element_init_Zr(tmp, this->pairing_);
      element_set(tmp, pow);

      element_mul(pow, tmp, const_cast<element_t&>(point.el_));

      element_clear(tmp);
    }

    element_clear(pow);

    return element_wrapper(value);
  }

  std::vector<element_wrapper> DkgTe::CreateSecretKeyContribution(
                                                const std::vector<element_wrapper>& polynomial) {
    std::vector<element_wrapper> secret_key_contribution(this->n_);
    for (size_t i = 0; i < this->n_; ++i) {
      element_t point;
      element_init_Zr(point, this->pairing_);
      element_set_si(point, i + 1);

      secret_key_contribution[i] = ComputePolynomialValue(polynomial, point);
    }

    return secret_key_contribution;
  }

  element_wrapper DkgTe::CreateSecretKeyShare(
                              const std::vector<element_wrapper>& secret_key_contribution) {
    element_t secret_key_share;
    element_init_Zr(secret_key_share, this->pairing_);
    element_set0(secret_key_share);

    for (size_t i = 0; i < this->n_; ++i) {
      element_t tmp;
      element_init_Zr(tmp, this->pairing_);

      element_set(tmp, secret_key_share);
      element_add(secret_key_share, tmp, const_cast<element_t&>(secret_key_contribution[i].el_));
    }

    if (element_is0(secret_key_share)) {
      throw std::runtime_error("Error, at least one secret key share is equal to zero");
    }

    return secret_key_share;
  }

  bool DkgTe::Verify(size_t idx, const element_wrapper& share, 
                const std::vector<element_wrapper>& verification_vector) {
    element_t value;
    element_init_G1(value, this->pairing_);

    for (size_t i = 0; i < this->t_; ++i) {
      element_t tmp1;
      element_init_Zr(tmp1, this->pairing_);
      element_set_si(tmp1, idx + 1);

      element_t tmp2;
      element_init_Zr(tmp2, this->pairing_);
      element_set_si(tmp2, i);

      element_t tmp3;
      element_init_Zr(tmp3, this->pairing_);
      element_pow_zn(tmp3, tmp1, tmp2);

      element_t tmp4;
      element_init_G1(tmp4, this->pairing_);
      element_mul_zn(tmp4, const_cast<element_t&>(verification_vector[i].el_), tmp3);

      if (i == 0) {
        element_set(value, tmp4);
      } else {
        element_t tmp;
        element_init_G1(tmp, this->pairing_);
        element_set(tmp, value);

        element_clear(value);
        element_init_G1(value, this->pairing_);

        element_add(value, tmp, tmp4);

        element_clear(tmp);
      }

      element_clear(tmp1);
      element_clear(tmp2);
      element_clear(tmp3);
      element_clear(tmp4);
    }

    element_t mul;
    element_init_G1(mul, this->pairing_);
    element_mul_zn(mul, this->generator_, const_cast<element_t&>(share.el_));

    return (element_cmp(value, mul) == 0);
  }

}  // namespace encryption
