#pragma once


#ifdef USE_MCL
#include "mcl/fr.hpp"
#include "mcl/fq.hpp"
#include "mcl/g1.hpp"
#include "mcl/g2.hpp"
#include "mcl/gt.hpp"
#include "mcl/pairing.hpp"
#include "mcl/init.hpp"

namespace algebra {
    using FrScalar  = mcl_backend::FrScalar;
    using FqElement = mcl_backend::FqElement;
    using G1Point   = mcl_backend::G1Point;
    using G2Point   = mcl_backend::G2Point;
    using GTElement = mcl_backend::GTElement;

    using mcl_backend::pairing;
}

#else
#include "libff/fr.hpp"
#include "libff/fq.hpp"
#include "libff/g1.hpp"
#include "libff/g2.hpp"
#include "libff/gt.hpp"
#include "libff/pairing.hpp"
#include "libff/init.hpp"

namespace algebra {

    using FrScalar  = libff_backend::FrScalar;
    using FqElement = libff_backend::FqElement;
    using G1Point   = libff_backend::G1Point;
    using G2Point   = libff_backend::G2Point;
    using GTElement = libff_backend::GTElement;

}
#endif



namespace algebra {
    
    // base for field element representation when converting to / from string
    enum class Base {
        BASE_HEXA = 16,
        BASE_DEC  = 10
    };

inline void init_curve() {
#ifdef USE_MCL
    mcl_backend
#else
    libff_backend
#endif
    ::init_curve();
}

GTElement pairing(const G1Point& g1, const G2Point& g2) {
    return 

#ifdef USE_MCL
    mcl_backend
#else
    libff_backend
#endif
    ::pairing(g1, g2);

}


}

