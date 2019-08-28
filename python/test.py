#!/usr/bin/env python3
# encoding: utf-8

import sys
sys.path.insert( 0, './build/lib.linux-x86_64-3.6' )

import libdkgpythond as dkgpython
from dkgpython import dkg


d = dkg(1, 2)

pola = d.GeneratePolynomial()
vva = d.VerificationVector(pola)
skca = d.SecretKeyContribution(pola)

polb = d.GeneratePolynomial()
vvb = d.VerificationVector(polb)
skcb = d.SecretKeyContribution(polb)

res = d.Verification(0, skca[1], vva)

print(res)
