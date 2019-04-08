#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <string>
#include <vector>
#include <utility>

#include <third_party/cryptlite/sha256.h>

namespace signatures {

  class bls {
    public:
      bls(const size_t t, const size_t n);

      std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> KeyGeneration();
      
      libff::alt_bn128_G1 Hashing(const std::string& message,
                                  std::string (*hash_func)(const std::string& str) = 
                                               cryptlite::sha256::hash_hex);

      libff::alt_bn128_G1 Signing(const libff::alt_bn128_G1 hash,
                                  const libff::alt_bn128_Fr secret_key);

      bool Verification(const libff::alt_bn128_G1 hash, const libff::alt_bn128_G1 sign,
                        const libff::alt_bn128_G2 public_key);

      std::pair<libff::alt_bn128_Fr, libff::alt_bn128_G2> KeysRecover(const std::vector<libff::alt_bn128_Fr>& coeffs,
                                                  const std::vector<libff::alt_bn128_Fr>& shares);

      libff::alt_bn128_G1 SignatureRecover(const std::vector<libff::alt_bn128_G1>& shares,
                                          const std::vector<libff::alt_bn128_Fr>& coeffs);

      std::vector<libff::alt_bn128_Fr> LagrangeCoeffs(const std::vector<size_t>& idx);

    private:
      const size_t t = 0;

      const size_t n = 0;
  };

}  // namespace signatures
