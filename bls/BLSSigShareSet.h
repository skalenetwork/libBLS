//
// Created by kladko on 7/5/19.
//

#ifndef SKALED_BLSSIGSHARESET_H
#define SKALED_BLSSIGSHARESET_H


#include <stdlib.h>
#include <mutex>
#include <string>
#include "bls.h"

class BLSSignature;

class BLSSigShareSet {

    size_t totalSigners;
    size_t requiredSigners;

    recursive_mutex sigSharesMutex;


    map<size_t, shared_ptr< BLSSigShare > > sigShares;

public:

    BLSSigShareSet( size_t requiredSigners, size_t totalSigners );

    bool isEnough();

    bool addSigShare( shared_ptr< BLSSigShare > _sigShare);

    unsigned long getTotalSigSharesCount();
    shared_ptr< BLSSigShare > getSigShareByIndex(size_t _index);
    shared_ptr<BLSSignature> merge();
};



#endif  // SKALED_BLSSIGSHARESET_H-
