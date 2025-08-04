#include "g2.hpp"
#include "utils.hpp"

namespace libff_backend {


std::vector<std::string> G2Point::toStringVector(int base) {
    to_affine_coordinates();
    return { 
        fieldElementToString( value.X.c0, base ), 
        fieldElementToString( value.X.c1, base ),
        fieldElementToString( value.Y.c0, base ), 
        fieldElementToString( value.Y.c1, base ) 
    };
}

}