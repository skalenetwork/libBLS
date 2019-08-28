#!/usr/bin/env python3
# encoding: utf-8

print( "-- 1" )

import sys
sys.path.insert( 0, './build/lib.linux-x86_64-3.5' )
#sys.path.insert( 0, '../../build/libbls' )
#sys.path.insert( 0, '/home/oleh/.config/sublime-text-3/Packages/User/cpp-ethereum/build/libbls' )


#import libdkgpythond as dkgpython
import dkgpython
from dkgpython import dkg


d = dkg(1, 2)

pola = d.GeneratePolynomial()
#pola = ["14725910850446911833450205568236830688398504023393148469553239919786991702305"]
vva = d.VerificationVector(pola)
skca = d.SecretKeyContribution(pola)

polb = d.GeneratePolynomial()
#polb = ["6394447785397553686901326588180527808650938069018909243310377932659101895816"]
vvb = d.VerificationVector(polb)
skcb = d.SecretKeyContribution(polb)

'''
print(skca)
print(skcb)
print(vva)
print(vvb)
'''

res = d.Verification(0, skca[1], vva)

print(res)


#9210798821649637688633130671680105717534167047277752706223109747443659463870 19005987600981761581276952375767750584688953476234475768468038114703621283548 21465446279705814258424621638550019579240771758443404240324098929356436639774 99083191187272539769227777726384476020534105984682003800823503366583670497 14517002984481287362672699675675069632413705759446770937645184717097057638085 21574601642802291667021457988840867807288943699962199420265729401475021593363 

#14924971649073427604242935522998874904548660137627087705344043202417060671482 14349344611390394239564361375430224334903532950465346183253813043383480792196 15924443201639242765462100808931527022124383765431732437578279824351711379258 4828837673488444298416928356254636310042488669752612706371932345864448836404 17212638407544333221909190132838782977777242839037374827335173128347249708814 8629862434183683835661911701542158691781344756421751108845496995791688841763 