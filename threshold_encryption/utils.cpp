#include <threshold_encryption/utils.h>

libff::alt_bn128_G1 MapToGroup(const std::string& message) {
  /*uint64_t i = 0;
  
  while (i < libff::alt_bn128_Fq::num_bits) {
    std::pair<libff::alt_bn128_Fq, size_t> hash = Hash(i || message);
    auto x = hash.first;
    auto b = hash.second;

    if (!IsQuadraticResidue(CurveEquation(x))) {
      ++i;
      continue;
    }

    libff::alt_bn128_Fq y_1 = SquareRoot(CurveEquation(x));
    libff::alt_bn128_Fq y_2 = -y_1;

    mpz_t v;
    mpz_init(v);

    mpz_t u;
    mpz_init(u);
    
    y_1.as_bigint().to_mpz(v);
    y_2.as_bigint().to_mpz(u);

    if (v < u) {
      std::swap(y_1, y_2);
    }

    mpz_clear(v);
    mpz_clear(u);

    libff::alt_bn128_Fq y = (b == 0 ? y_1 : y_2);

    return libff::alt_bn128_G1(x, y, libff::alt_bn128_Fq::one());
  }

  if (i == libff::alt_bn128_Fq::num_bits) {
    throw std::runtime_error("hashing into elliptic curve failed\n");
  }*/
}

inline libff::alt_bn128_Fq CurveEquation(const libff::alt_bn128_Fq& field_elem) {
  return ((field_elem ^ 3) + libff::alt_bn128_Fq(3)); 
}

bool IsQuadraticResidue(const libff::alt_bn128_Fq& field_elem) {
  return (field_elem ^ field_elem.euler) == libff::alt_bn128_Fq::one();
}

libff::alt_bn128_Fq SquareRoot(const libff::alt_bn128_Fq& field_elem) {
  if (!IsQuadraticResidue(field_elem)) {
    throw std::runtime_error("Given element is a quadratic nonresiue");
  }

  return field_elem.sqrt();  
}