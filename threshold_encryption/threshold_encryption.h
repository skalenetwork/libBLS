#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <string>
#include <tuple>
#include <vector>
#include <utility>

#include <third_party/cryptlite/sha256.h>

namespace encryption{
  typedef std::tuple<libff::alt_bn128_G1, std::string, libff::alt_bn128_G2> Ciphertext;

  size_t alt_bn128_embedding_degree = 12;

  class TE{
    private:
      const size_t t_ = 0;

      const size_t n_ = 0;

      const size_t index_ = 0;

      const libff::alt_bn128_Fr secret_key_ = 0;

      const libff::alt_bn128_G2 public_key_ = libff::alt_bn128_G2::one();

    public:
      TE(const size_t t, const size_t n, const size_t index, const char* secret_key, const libff::alt_bn128_G2 public_key);

      libff::alt_bn128_G2 HashingToG2(libff::alt_bn128_G1 group_elem, const std::string& message,
                                            std::string (*hash_func)(const std::string& str) = 
                                               cryptlite::sha256::hash_hex);

      std::string HashingFromG2(libff::alt_bn128_G2 group_elem,
                                            std::string (*hash_func)(const std::string& str) = 
                                               cryptlite::sha256::hash_hex);

      Ciphertext Encryption(const std::string& message, const libff::alt_bn128_G2 common_public);

      std::pair<libff::alt_bn128_G1, size_t> Decryption(const Ciphertext& ciphertext);

      bool Verification(const Ciphertext& ciphertext, libff::alt_bn128_G1 decrypted);

      std::string ShareCombining(const Ciphertext& ciphertext, const std::vector<std::pair<libff::alt_bn128_G1, size_t>>& decrypted);

      std::vector<libff::alt_bn128_Fr> LagrangeCoeffs(const std::vector<size_t>& idx);

      libff::alt_bn128_G1 G2ToG1(const libff::alt_bn128_G2& other);

      libff::alt_bn128_G1 FrobeniusTrace(const libff::alt_bn128_G2& other);
  };
}  // namespace encryption
