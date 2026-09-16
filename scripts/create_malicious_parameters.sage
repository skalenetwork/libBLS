#!/usr/bin/env sage

from sage.all import GF,EllipticCurve
import json
import sys
def CreateCurves():
    """Construct everything we need:
        G2 order
        identity element for G2
        smallest factor of G2 cofactor
        a point on the curve that hosts G2 but in the """
    # We are constructing the elliptic curves used in DKG and BLS
    q=21888242871839275222246405745257275088696311157297823662689037894645226208583
    fq=GF(q)
    nonsqr=21888242871839275222246405745257275088696311157297823662689037894645226208582
    fq2=GF(q**2,name='x',modulus= [1,0,-nonsqr])
    x=fq2.gen()
    G1=EllipticCurve(fq,[0,3])
    eG2=EllipticCurve(fq2,[0,3*((9+x)^(-1))]) # elliptic Curve that is used to create subgroup G2. It is not actually G2
    oneG2=eG2(10857046999023057135944570762232829481370756359578518086990519993285655852781+
             x*11559732032986387107991004021392285783925812861821192530917403151452391805634,
            8495653923123431417604973247489272438418190587263600148770280649306958101930+
            x*4082367875863433681332203403145435568316851327593401208105741076214120093531)
    orderG1G2=21888242871839275222246405745257275088548364400416034343698204186575808495617
    cofactorG2=21888242871839275222246405745257275088844257914179612981679871602714643921549
    # We find the smallest factor of G2's cofactor on the elliptic curve,
    # where G2 is defined to create another subgroup in this elliptic curve
    smallestFactorOfCofactor=cofactorG2.factor()[0][0]
    # We compute a cofactor to our new group
    subgroupConfinementCofactor=(orderG1G2*(cofactorG2//smallestFactorOfCofactor))
    # Now we generate random points on G2's curve and see if we can create the smallest subgroup from them
    while True:
        randomPoint=eG2.random_point()
        subgroupPoint=randomPoint*subgroupConfinementCofactor
        # If we multiply the point by our cofactor and get the identity, then we can't use it
        if subgroupPoint.is_zero():
            continue
        else:
            break
    return (orderG1G2,oneG2,smallestFactorOfCofactor,subgroupPoint)

from copy import deepcopy
def CreateMaliciousPolynomialSystem(t,cofactor):
    """This function creates a malicious polynomial that allows n-t+1 malicious nodes to DoS
    the system. For simplicity nodes from 1 to t are deemed honest.
    Here we create a system of t linear equations from polynomials of type:
    a_0+a_1*i+a_2*i^2+...+a_t*i^t=0, where i is an index, and solve this system"""
    # Define the field
    f=GF(cofactor)
    equations=[]
    # Define equations a_1*i+a_2*i^2+...+a_t*i^t=-a_0, where a_0 is 1 for simplicity
    for i in range(1,t+1):
        temp=i
        equation=[]
        for j in range(t):
            equation.append(f(temp))
            temp*=i
        equations.append(equation)
    a_0s=[f(-1)]*t
    # Solve the system of linear equations
    for i in range(0,t):
        if equations[i][i]==0:
            # search for another equation, where coefficient at index i is not zero
            for j in range(i+1,t):
                if equations[j][i]!=0:
                    equations=equations[:i]+[equations[j]]+equations[i+1:j]+[eqautions[i]]+eqautions[j:]
                    a_0s=a_0s[:i]+[a_0s[j]]+a_0s[i+1:j]+[a_0s[i]]+a_0s[j+1:]
                    break
        element_inverse=equations[i][i]**-1
        for j in range(i,t):
            equations[i][j]*=element_inverse
        a_0s[i]*=element_inverse
        for j in range(0,t):
            if j==i:
                continue
            coefficient=equations[j][i]
            for k in range(i,t):
                equations[j][k]-=equations[i][k]*coefficient
            a_0s[j]-=a_0s[i]*coefficient
            
    # Check the resulting polynomial
    for i in range(1,t+1):
        temp=i
        result=f(1)
        for j in range(t):
            result+=f(temp*a_0s[j])
            temp*=i
        assert (result==0)
    return [1]+a_0s

# Get subgroup order and a point in E2 subgroup (not G2)
(_,_,subgroupOrder,subgroupPoint)=CreateCurves()

# Create a polynomial for t=10 (numsigned=11)
polynomial=CreateMaliciousPolynomialSystem(10,subgroupOrder)

# Get x,y of subgroup point
spx,spy=subgroupPoint.xy()

# Save all paramters to 1 dict
parameters={'polynomial':list(map(str,polynomial)), 'point':{'x':list(map(str,spx._vector_())),'y':list(map(str,spy._vector_()))}}

# Print parameters
print (parameters)

# Save parameters to 'parameters.json'
with open('parameters.json','w') as f:
    f.write(json.dumps(parameters))

