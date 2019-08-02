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

  @file bls.cpp
  @author Oleh Nikolaiev
  @date 2018
*/


#include <bls/bls.h>

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <thread>
#include <bitset>

#include <boost/multiprecision/cpp_int.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>

#include "BLSutils.h"

namespace signatures {

    Bls::Bls(const size_t t, const size_t n) : t_(t), n_(n) {
        libff::init_alt_bn128_params();  // init all parameters for math operations
    }

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> Bls::KeyGeneration() {
        // generate secret and public KeysRecover
        libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::random_element();  // secret key generation

        while (secret_key == libff::alt_bn128_Fr::zero()) {
            secret_key = libff::alt_bn128_Fr::random_element();
        }

        const libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();  // public key generation

        return std::make_pair(secret_key, public_key);
    }

    libff::alt_bn128_G1 Bls::Hashing(const std::string &message,
                                     std::string (*hash_func)(const std::string &str)) {
        std::string sha256hex = hash_func(message);

        boost::multiprecision::uint256_t num = 0;
        boost::multiprecision::uint256_t pow = 1;
        for (auto sym : sha256hex) {
            // converting from hex to bigint
            num += ((sym >= 'a') * 10 + static_cast<int>((sym - 'a'))) * pow;
            pow *= 16;
        }

        std::string s = num.convert_to<std::string>();

        const libff::alt_bn128_G1 hash = libff::alt_bn128_Fr(s.c_str()) * libff::alt_bn128_G1::one();

        return hash;
    }

    libff::alt_bn128_G1 Bls::HashtoG1(std::shared_ptr<std::array< uint8_t, 32>> hash_byte_arr) {

        libff::alt_bn128_Fq x1 (BLSutils::HashToFq(hash_byte_arr));

        libff::alt_bn128_G1 result;

        while  (true) {
            libff::alt_bn128_Fq y1_sqr = x1^3;
            y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

            libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

            if (euler == libff::alt_bn128_Fq::one() || euler == libff::alt_bn128_Fq::zero()) {  // if y1_sqr is a square
                result.X = x1;
                result.Y = y1_sqr.sqrt();
                break;
            } else {
                x1 = x1 + 1;
            }
        }
        result.Z = libff::alt_bn128_Fq::one();

        return result;
    }

    std::pair<libff::alt_bn128_G1, std::string> Bls::HashtoG1withHint(std::shared_ptr< std::array< uint8_t, 32>> hash_byte_arr){

        libff::alt_bn128_G1 point;
        libff::alt_bn128_Fq counter = libff::alt_bn128_Fq::zero();

        libff::alt_bn128_Fq x1(BLSutils::HashToFq(hash_byte_arr));
        while  (true) {
            libff::alt_bn128_Fq y1_sqr = x1^3;
            y1_sqr = y1_sqr + libff::alt_bn128_coeff_b;

            libff::alt_bn128_Fq euler = y1_sqr ^ libff::alt_bn128_Fq::euler;

            if ( (euler == libff::alt_bn128_Fq::one() || euler == libff::alt_bn128_Fq::zero()) && !x1.is_zero() ) {  // if y1_sqr is a square
                point.X = x1;
                point.Y = y1_sqr.sqrt();
                break;
            } else {
                counter = counter + libff::alt_bn128_Fq::one();
                x1 = x1 + libff::alt_bn128_Fq::one();
            }
        }
        point.Z = libff::alt_bn128_Fq::one();

        return std::make_pair(point, BLSutils::ConvertToString(counter) );
    }

    libff::alt_bn128_G1 Bls::HashBytes(const char *raw_bytes, size_t length,
                                       std::string (*hash_func)(const std::string &str)) {
        std::string from_bytes(raw_bytes, length);

        std::cout << from_bytes << '\n';

        libff::alt_bn128_G1 hash = this->Hashing(from_bytes, *hash_func);

        return hash;
    }

    libff::alt_bn128_G1 Bls::Signing(const libff::alt_bn128_G1 hash,
                                     const libff::alt_bn128_Fr secret_key) {
        // sign a message with its hash and secret key
        // implemented constant time signing

        if (secret_key == libff::alt_bn128_Fr::zero()) {
            throw std::runtime_error("Error, secret key share is equal to zero");
        }

        std::clock_t c_start = std::clock();  // hash

        const libff::alt_bn128_G1 sign = secret_key.as_bigint() * hash;  // sign

        std::clock_t c_end = std::clock();

        std::this_thread::sleep_for(std::chrono::microseconds(10000 -
                                                              1000000 * (c_end - c_start) / CLOCKS_PER_SEC));

        return sign;
    }

    bool Bls::Verification(const std::string &to_be_hashed, const libff::alt_bn128_G1 sign,
                           const libff::alt_bn128_G2 public_key) {
        // verifies that a given signature corresponds to given public key

        if (!sign.is_well_formed() || !public_key.is_well_formed()) {
            throw std::runtime_error("Error, incorrect input data to verify signature");
        }

        if (libff::alt_bn128_modulus_r * sign != libff::alt_bn128_G1::zero()) {
            throw std::runtime_error("Error, signature is invalid");
        }

        libff::alt_bn128_G1 hash = this->Hashing(to_be_hashed);

        return (libff::alt_bn128_ate_reduced_pairing(sign, libff::alt_bn128_G2::one()) ==
                libff::alt_bn128_ate_reduced_pairing(hash, public_key));
        // there are several types of pairing, it does not matter which one is chosen for verification
    }

    bool Bls::Verification(std::shared_ptr< std::array< uint8_t, 32>> hash_byte_arr, const libff::alt_bn128_G1 sign,
                           const libff::alt_bn128_G2 public_key) {
        // verifies that a given signature corresponds to given public key

        if (!sign.is_well_formed() || !public_key.is_well_formed()) {
            throw std::runtime_error("Error, incorrect input data to verify signature");
        }

        if (libff::alt_bn128_modulus_r * sign != libff::alt_bn128_G1::zero()) {
            throw std::runtime_error("Error, signature is invalid");
        }

        libff::alt_bn128_G1 hash = this->HashtoG1(hash_byte_arr);

        return (libff::alt_bn128_ate_reduced_pairing(sign, libff::alt_bn128_G2::one()) ==
                libff::alt_bn128_ate_reduced_pairing(hash, public_key));
        // there are several types of pairing, it does not matter which one is chosen for verification
    }

    std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> Bls::KeysRecover(
            const std::vector<libff::alt_bn128_Fr> &coeffs,
            const std::vector<libff::alt_bn128_Fr> &shares) {
        if (shares.size() < this->t_ || coeffs.size() < this->t_) {
            throw std::runtime_error("Error, not enough participants in the threshold group");
        }

        libff::alt_bn128_Fr secret_key = libff::alt_bn128_Fr::zero();

        for (size_t i = 0; i < this->t_; ++i) {
            if (shares[i] == libff::alt_bn128_Fr::zero()) {
                throw std::runtime_error("Error, at least one secret key share is equal to zero");
            }
            secret_key += coeffs[i] * shares[i];  // secret key recovering using Lagrange Interpolation
        }

        const libff::alt_bn128_G2 public_key = secret_key * libff::alt_bn128_G2::one();  // public key recovering

        return std::make_pair(secret_key, public_key);
    }

    libff::alt_bn128_G1 Bls::SignatureRecover(const std::vector<libff::alt_bn128_G1> &shares,
                                              const std::vector<libff::alt_bn128_Fr> &coeffs) {
        if (shares.size() < this->t_ || coeffs.size() < this->t_) {
            throw std::runtime_error("Error, not enough participants in the threshold group");
        }

        libff::alt_bn128_G1 sign = libff::alt_bn128_G1::zero();

        for (size_t i = 0; i < this->t_; ++i) {
            if (!shares[i].is_well_formed()) {
                throw std::runtime_error("Error, incorrect input data to recover signature");
            }
            sign = sign + coeffs[i] * shares[i];  // signature recovering using Lagrange Coefficients
        }

        return sign;  // first element is hash of a receiving message
    }

    std::vector<libff::alt_bn128_Fr> Bls::LagrangeCoeffs(const std::vector<size_t> &idx) {
        if (idx.size() < this->t_) {
            throw std::runtime_error("Error, not enough participants in the threshold group");
        }

        std::vector<libff::alt_bn128_Fr> res(this->t_);

        libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

        for (size_t i = 0; i < this->t_; ++i) {
            w *= libff::alt_bn128_Fr(idx[i]);
        }

        for (size_t i = 0; i < this->t_; ++i) {
            libff::alt_bn128_Fr v = libff::alt_bn128_Fr(idx[i]);

            for (size_t j = 0; j < this->t_; ++j) {
                if (j != i) {
                    if (libff::alt_bn128_Fr(idx[i]) ==
                        libff::alt_bn128_Fr(idx[j])) {
                        throw std::runtime_error(
                                "Error during the interpolation, have same indexes in list of indexes");
                    }

                    v *= (libff::alt_bn128_Fr(idx[j]) -
                          libff::alt_bn128_Fr(idx[i]));  // calculating Lagrange coefficients
                }
            }

            res[i] = w * v.invert();
        }

        return res;
    }

}  // namespace signatures
