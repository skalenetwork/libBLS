#ifdef MCL

#include "../interface/init.hpp"
#include "backends/interface/curve_contract_altbn128.hpp"
#include <mcl/bn.hpp>

namespace libBLS {
namespace algebra {

void initCurve() {
    mcl::bn::CurveParam cp = mcl::bn::BN_SNARK1;
    mcl::bn::initPairing(cp);
}

}  // namespace algebra
}  // namespace libBLS

#endif // MCL