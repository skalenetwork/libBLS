#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

class BLSutils{
  //  static bool was_initialized;
    public:
    template<class T>
    static std::string ConvertToString(T field_elem);
    static void initBLS();
    static int sgn0 (libff::alt_bn128_Fq);
};

template<class T>
std::string BLSutils::ConvertToString(T field_elem) {
    mpz_t t;
    mpz_init(t);

    //if (typeid(field_elem) != typeid(libff::bigint<4>))
     field_elem.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase (t, 10) + 2];

    char * tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    std::string output = tmp;

    return output;
}