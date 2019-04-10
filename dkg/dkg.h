#pragma once

#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp.hpp>

namespace signatures {

class Dkg {
 public:
    Dkg(const size_t t, const size_t n);

    std::vector<libff::alt_bn128_Fr> GeneratePolynomial();

    std::vector<libff::alt_bn128_G2> VerificationVector(
                                              const std::vector<libff::alt_bn128_Fr>& polynomial);

    libff::alt_bn128_Fr PolynomialValue(const std::vector<libff::alt_bn128_Fr>& pol,
                                                                        libff::alt_bn128_Fr point);

    std::vector<libff::alt_bn128_Fr> SecretKeyContribution(
                                              const std::vector<libff::alt_bn128_Fr>& polynomial);

    libff::alt_bn128_Fr SecretKeyShareCreate(
                                  const std::vector<libff::alt_bn128_Fr>& secret_key_contribution);

    bool Verification(size_t idx, libff::alt_bn128_Fr share,
                        const std::vector<libff::alt_bn128_G2>& verification_vector);

 private:
    const size_t t_ = 0;

    const size_t n_ = 0;
};

}  // namespace signatures
