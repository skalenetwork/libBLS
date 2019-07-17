
#include <memory>
#include <iostream>
#include <string>


#include "bls.h"

template<class T>
std::string ConvertToString(T field_elem) {
    mpz_t t;
    mpz_init(t);

    field_elem.as_bigint().to_mpz(t);

    char arr[mpz_sizeinbase (t, 10) + 2];

    char * tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    std::string output = tmp;

    return output;
}



