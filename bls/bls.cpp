#include <bls/bls.h>

#include <chrono>
#include <ctime>
#include <stdexcept>
#include <thread>

#include <boost/multiprecision/cpp_int.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>

namespace signatures {

  bls::bls(const size_t t, const size_t n) : t(t), n(n) {
    libff::init_alt_bn128_params();  // init all parameters for math operations
  }

  std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> bls::KeyGeneration() {
    // generate secret and public KeysRecover
    libff::alt_bn128_Fr x = libff::alt_bn128_Fr::random_element();  // secret key generation

    while (x == libff::alt_bn128_Fr::zero()) {
      x = libff::alt_bn128_Fr::random_element();
    }

    const libff::alt_bn128_G2 p = x * libff::alt_bn128_G2::one();  // public key generation

    return std::make_pair(x, p);
  }

  libff::alt_bn128_G1 bls::Hashing(const std::string& message,
                                  std::string (*hash_func)(const std::string& str)) {
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

  libff::alt_bn128_G1 bls::Signing(const libff::alt_bn128_G1 hash, const libff::alt_bn128_Fr secret_key) {
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

  bool bls::Verification(const libff::alt_bn128_G1 hash, const libff::alt_bn128_G1 sign,
                         const libff::alt_bn128_G2 public_key) {
    // verifies that a given signature corresponds to given public key

    if (!hash.is_well_formed() || !sign.is_well_formed() || !public_key.is_well_formed()) {
      throw std::runtime_error("Error, incorrect input data to verify signature");
    }

    return (libff::alt_bn128_ate_reduced_pairing(sign, libff::alt_bn128_G2::one()) ==
            libff::alt_bn128_ate_reduced_pairing(hash, public_key));  // there are several types of pairing, it does not matter which one is chosen for verification
  }

  std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> bls::KeysRecover(const std::vector<libff::alt_bn128_Fr>& coeffs,
                                                  const std::vector<libff::alt_bn128_Fr>& shares) {
    if (shares.size() < this->t || coeffs.size() < this->t) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    libff::alt_bn128_Fr sk = libff::alt_bn128_Fr::zero();

    for (size_t i = 0; i < this->t; ++i) {
      if (shares[i] == libff::alt_bn128_Fr::zero()) {
        throw std::runtime_error("Error, at least one secret key share is equal to zero");
      }
      sk += coeffs[i] * shares[i];  // secret key recovering using Lagrange Interpolation
    }

    const libff::alt_bn128_G2 pk = sk * libff::alt_bn128_G2::one();  // public key recovering

    return std::make_pair(sk, pk);
  }

  libff::alt_bn128_G1 bls::SignatureRecover(const std::vector<libff::alt_bn128_G1>& shares,
                                            const std::vector<libff::alt_bn128_Fr>& coeffs) {
    if (shares.size() < this->t || coeffs.size() < this->t) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    libff::alt_bn128_G1 sign = libff::alt_bn128_G1::zero();

    for (size_t i = 0; i < this->t; ++i) {
      if (!shares[i].is_well_formed()) {
        throw std::runtime_error("Error, incorrect input data to recover signature");
      }
      sign = sign + coeffs[i] * shares[i];  // signature recovering using Lagrange Coefficients
    }

    return sign;  // first element is hash of a receiving message
  }

  std::vector<libff::alt_bn128_Fr> bls::LagrangeCoeffs(const std::vector<size_t>& idx) {
    if (idx.size() < this->t) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    std::vector<libff::alt_bn128_Fr> res(this->t);

    libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

    for (size_t j = 0; j < this->t; ++j) {
      w *= libff::alt_bn128_Fr(idx[j]);
    }

    for (size_t i = 0; i < this->t; ++i) {
      libff::alt_bn128_Fr v = libff::alt_bn128_Fr(idx[i]);

      for (size_t j = 0; j < this->t; ++j) {
        if (j != i) {
          if (libff::alt_bn128_Fr(idx[i]) ==
              libff::alt_bn128_Fr(idx[j])) {
            throw std::runtime_error("Error during the interpolation, have same indexes in list of indexes");
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
