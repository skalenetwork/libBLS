#include <threshold_encryption/threshold_encryption.h>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>

#include <valarray>

template<class T>
std::string ConvertToString(T field_elem) {
  mpz_t t;
  mpz_init(t);

  field_elem.as_bigint().to_mpz(t);

  char * tmp = mpz_get_str(NULL, 10, t);
  mpz_clear(t);

  std::string output = tmp;

  return output;
}

namespace encryption {
  typedef std::tuple<libff::alt_bn128_G1, std::string, libff::alt_bn128_G2> Ciphertext;

  TE::TE(const size_t t, const size_t n, const size_t index, const char* secret_key,
                                              const libff::alt_bn128_G2 public_key) : 
                    t_(t), n_(n), index_(index), public_key_(public_key), secret_key_(secret_key) {
    libff::init_alt_bn128_params();
  }

  std::string TE::ShareCombining(const Ciphertext& ciphertext,
                            const std::vector<std::pair<libff::alt_bn128_G1, size_t>>& decrypted) {
    if (decrypted.size() != this->t_) {
      throw std::runtime_error("Incorrect decrypted data for Share Combining");
    }

    libff::alt_bn128_G1 U = std::get<0>(ciphertext);
    std::string V = std::get<1>(ciphertext);
    libff::alt_bn128_G2 W = std::get<2>(ciphertext);

    libff::alt_bn128_G2 H = this->HashingToG2(U, V);

    if (libff::alt_bn128_ate_reduced_pairing(libff::alt_bn128_G1::one(), W) !=
                                                    libff::alt_bn128_ate_reduced_pairing(U, H)) {
      throw std::runtime_error("In this case, all the decryption shares are of the form i,false");
    } else {
      std::string message = "";

      std::vector<size_t> indexes(this->t_);
      for (size_t i = 0; i < this->t_; ++i) {
        indexes[i] = decrypted[i].second;
      }

      std::vector<libff::alt_bn128_Fr> coeffs = LagrangeCoeffs(indexes);
      
      libff::alt_bn128_G2 to_be_hashed = libff::alt_bn128_G2::zero();

      for (size_t i = 0; i < this->t_; ++i) {
        to_be_hashed = to_be_hashed + coeffs[i] * decrypted[i].first;
      }

      std::string hash = this->HashingFromG2(to_be_hashed);
      //message = hash ^ V;
      return message;
    }
  }

  std::string TE::HashingFromG2(libff::alt_bn128_G2 group_elem,
                                            std::string (*hash_func)(const std::string& str)) {
    std::string hash = hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.X.c0)) +
                        hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.X.c1)) +
                        hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Y.c0)) +
                        hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Y.c1)) +
                        hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Z.c0)) +
                        hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Z.c1));

    return hash;
  }

  libff::alt_bn128_G2 TE::HashingToG2(libff::alt_bn128_G1 group_elem, const std::string& message,
                                            std::string (*hash_func)(const std::string& str)) {
    std::string sha256hex = hash_func(message);

    libff::alt_bn128_Fr num = libff::alt_bn128_Fr::zero();
    libff::alt_bn128_Fr pow = libff::alt_bn128_Fr::one();

    sha256hex += hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.X))
                + hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Y))
                + hash_func(ConvertToString<libff::alt_bn128_Fq>(group_elem.Z));

    for (auto& sym : sha256hex) {
      num += (static_cast<libff::alt_bn128_Fr>(sym >= 'a') * libff::alt_bn128_Fr(10) + static_cast<libff::alt_bn128_Fr>((sym - 'a'))) * pow;
      pow *= libff::alt_bn128_Fr(16);
    }

    libff::alt_bn128_G2 hash = num * libff::alt_bn128_G2::one();

    return hash;
  }

  Ciphertext TE::Encryption(const std::string& message, const libff::alt_bn128_G2 common_public) {
    libff::alt_bn128_Fr r = libff::alt_bn128_Fr::random_element();
    while (r == libff::alt_bn128_Fr::zero()) {
      r = libff::alt_bn128_Fr::random_element();
    }

    libff::alt_bn128_G1 U = r * libff::alt_bn128_G1::one();

    libff::alt_bn128_G2 Y = r * common_public;

    std::string hash = this->HashingFromG2(Y);

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
    for (size_t i = 0; i < V.size(); ++i) {
      V[i] += static_cast<char>(res[i]);
    }

    libff::alt_bn128_G2 W = r * this->HashingToG2(U, V);

    return std::make_tuple(U, V, W);
  }

  std::pair<libff::alt_bn128_G1, size_t> TE::Decryption(const Ciphertext& ciphertext) {
    libff::alt_bn128_G1 U = std::get<0>(ciphertext);
    std::string V = std::get<1>(ciphertext);
    libff::alt_bn128_G2 W = std::get<2>(ciphertext);

    libff::alt_bn128_G2 H = this->HashingToG2(U, V);

    bool res = (libff::alt_bn128_ate_reduced_pairing(libff::alt_bn128_G1::one(), W) ==
                                                      libff::alt_bn128_ate_reduced_pairing(U, H));

    if (res) {
      libff::alt_bn128_G1 return_res = this->secret_key_ * U;
      return std::make_pair(return_res, this->index_);
    } else {
      return std::make_pair(libff::alt_bn128_G1::zero(), this->index_);
    }
  }

  bool TE::Verification(const Ciphertext& ciphertext, libff::alt_bn128_G1 decrypted) {
    libff::alt_bn128_G1 U = std::get<0>(ciphertext);
    std::string V = std::get<1>(ciphertext);
    libff::alt_bn128_G2 W = std::get<2>(ciphertext);

    libff::alt_bn128_G2 H = this->HashingToG2(U, V);

    bool res = (libff::alt_bn128_ate_reduced_pairing(libff::alt_bn128_G1::one(), W) ==
                                                      libff::alt_bn128_ate_reduced_pairing(U, H));

    if (res) {
      if (decrypted == libff::alt_bn128_G1::zero()) {
        return false;
      } else {
        bool check = (libff::alt_bn128_ate_reduced_pairing(decrypted, libff::alt_bn128_G2::one())
                                    == libff::alt_bn128_ate_reduced_pairing(U, this->public_key_));
        if (check) {
          return true;
        } else {
          return false;
        }
      }
    } else {
      if (decrypted == libff::alt_bn128_G1::zero()) {
        return true;
      } else {
        return false;
      }
    }
  }

  libff::alt_bn128_G2 TE::FrobeniusMap(const libff::alt_bn128_G2& other, size_t pow) {
    libff::alt_bn128_G2 copy = other;
    //copy.to_affine_coordinates();

    libff::alt_bn128_Fq2 x = copy.X.Frobenius_map();
    libff::alt_bn128_Fq2 y = copy.Y.Frobenius_map();
    libff::alt_bn128_Fq2 z = copy.Z.Frobenius_map();

    return libff::alt_bn128_G2(x, y, z);
  }

  libff::alt_bn128_G1 TE::FrobeniusTrace(const libff::alt_bn128_G2& other) {
    libff::alt_bn128_G2 temp  = libff::alt_bn128_G2::zero();
    //temp.to_affine_coordinates();

    for (size_t i = 0; i < alt_bn128_embedding_degree; ++i) {
      temp = temp + TE::FrobeniusMap(other, i);
      //temp.to_affine_coordinates();
    }

    temp.print_coordintes();

    return libff::alt_bn128_G1(temp.X.c0, temp.Y.c0, temp.Z.c0);
  }

  libff::alt_bn128_G1 TE::G2ToG1(const libff::alt_bn128_G2& other) {
    libff::alt_bn128_G1 result = libff::alt_bn128_Fr("12").inverse() * this->FrobeniusTrace(other);

    return result;
  }

  std::vector<libff::alt_bn128_Fr> TE::LagrangeCoeffs(const std::vector<size_t>& idx) {
    if (idx.size() < this->t_) {
      throw std::runtime_error("Error, not enough participants in the threshold group");
    }

    std::vector<libff::alt_bn128_Fr> res(this->t_);

    libff::alt_bn128_Fr w = libff::alt_bn128_Fr::one();

    for (size_t j = 0; j < this->t_; ++j) {
      w *= libff::alt_bn128_Fr(idx[j]);
    }

    for (size_t i = 0; i < this->t_; ++i) {
      libff::alt_bn128_Fr v = libff::alt_bn128_Fr(idx[i]);

      for (size_t j = 0; j < this->t_; ++j) {
        if (j != i) {
          if (libff::alt_bn128_Fr(idx[i]) ==
              libff::alt_bn128_Fr(idx[j])) {
            throw std::runtime_error("Error during the interpolation, have same indexes in the list of indexes");
          }

          v *= (libff::alt_bn128_Fr(idx[j]) -
                libff::alt_bn128_Fr(idx[i]));  // calculating Lagrange coefficients
        }
      }

      res[i] = w * v.invert();
    }

    return res;
  }
}  // namespace encrtyption
