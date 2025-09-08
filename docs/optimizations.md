## This document describes steps taken into optimizing Elliptic Curve Algebra's performance

## Assumptions

* Groups: prime-order subgroups G1, G2 of order r; target group GT (multiplicative) of the same order.
* Pairing: e: G1 × G2 → GT is bilinear and non‑degenerate.
* Implementation hygiene: BN254/alt\_bn128 with G1 cofactor = 1 (so on‑curve implies in‑subgroup), G2 cofactor‑cleared or order‑checked at ingest; points normalized/affine or batch‑normalized.
* Notation: ML(P,Q) = Miller loop output in Fp^12\*; FE(x) = x^k with k = (p^12−1)/r (final exponentiation) mapping into GT. Negation in G1 written as −H.

---

### 1. Check once, use all

- Complete ciphertext validation, including pairing computation is done only once at receival of ciphertext.
- Every call after `ThresholdEncryption::validateEncryption` assumes ciphertext was already validated by this call.
- Even so, subsequent calls can still fail if for some reason the ciphertext got tampered with (say, someone got access to computer's RAM and tampered it)

#### Result
- Less 2 pairing computations on each call
- ~2x speedup compared to previous version

---

### 2. Optimizing Pairing Equality

#### Claim

`e(W,g2) == e(H,U)`  is equivalent to  `FE( ML(W,g2) * ML(−H,U) ) == 1_GT`.

#### Proof

1. Group equality via inverse: in any group, `A=B` iff `A * B^{-1} = 1`. Hence `e(W,g2)=e(H,U)` iff `e(W,g2)*e(H,U)^{-1}=1`.

2. Bilinearity gives inversion via negation: since `e(aP,Q)=e(P,Q)^a`, we get `e(−H,U)=e(H,U)^{-1}`.

3. Define Miller outputs: let `f1=ML(W,g2)`, `f2=ML(−H,U)`. By definition of FE: `FE(f1)=e(W,g2)`, `FE(f2)=e(−H,U)`.

4. FE is a homomorphism: `FE(xy)=(xy)^k = x^k y^k = FE(x) FE(y)`.

5. Combine: `FE(f1*f2) = FE(f1) FE(f2) = e(W,g2) e(−H,U) = e(W,g2) e(H,U)^{-1}`. This equals 1 iff `e(W,g2)=e(H,U)`.

**Conclusion.** Two Miller loops + one FE is algebraically equivalent to two full pairings, and strictly cheaper (one fewer FE).

#### Code changes

```C++

// --------------- OLD --------------- 
(...)
return pairing(g1P1.value, g1P2.value) == pairing(g1P2.value, g2P2.value)

// --------------- NEW --------------- 
(...)
// compute pairing equality for each element in the vector
mcl::Fp12 f1, f2;

// Two Miller loops (no final exponentiation yet)
mcl::millerLoop(f1, g1P1.value,  g2P1.value);    // f1 = ML(g1P1, g2P1)
G1BackendType g1P2Negatted = g1P2.value;
G1BackendType::neg(g1P2Negatted, g1P2.value);  // -g1P2
mcl::millerLoop(f2, g1P2Negatted, g2P2.value);         // f2 = ML(-g1P2, g2P2)

// Combine, then a single final exponentiation
f1 *= f2;                    // f1 = ML(g1P1,g2P1) * ML(-g1P2,g2P2)
mcl::finalExp(f1, f1);       // f1 = FE( ... )

return f1.isOne();           // product == 1 ?
```



#### Result
- Less 1 exponenciation of every pairing equality
- ~2x speedup compared to previous version

---

### 3. Caching common terms using batches

A batch of decrpyion shares must be validated using the test `e(Wi,g2) ?= e(H,Ui)` for i=1..n.
Both `W` and `H` are derived from the same common ciphertext. This is an invariant in the loop, thus `W` and `H` are constant.

#### Claim

Let `Hminus := −H`, computed once. For each i, replacing `ML(−H,Ui)` by `ML(Hminus,Ui)` yields the identical value; thus reusing the single precomputed `Hminus` across the batch is exactly equivalent to recomputing `−H` per item.

### Proof

1. Negation is a deterministic automorphism of G1: ν(P)=−P, with ν(ν(P))=P and ν(P+Q)=ν(P)+ν(Q). In affine coords it is (x,y) → (x,−y mod p).

2. Independence from Ui: `Hminus` depends only on H. For every i, recomputing `−H` produces the same group element `Hminus`. Thus the Miller‑loop input pair is the same: `(Hminus, Ui)`.

3. Determinism of Miller loop: with fixed inputs, ML(·,·) is deterministic. Therefore `ML(−H,Ui) = ML(Hminus,Ui)` for each i.

**Conclusion.** Precomputing `Hminus` once and reusing it across the batch is algebraically exact and avoids redundant negations/normalizations. It does not change acceptance/rejection outcomes nor the ability to isolate bad items when followed by per‑item checks or group testing.

#### Code changes

```C++
// negate g1P2 only once
G1BackendType g1P2Negatted = batch.commonG1P2.get().value;
G1BackendType::neg(g1P2Negatted, batch.commonG1P2.get().value);  // -g1P2

std::vector< bool > isValidVec(batch.size, true);

// Do each pairing equality individually, and identify which ones are invalid
for (size_t i = 0; i < batch.size; ++i) {
    const algebra::G2Point& currentG2P1 = batch.g2P1s[i].get();
    const algebra::G2Point& currentG2P2 = batch.g2P2s[i].get();

    // compute pairing equality for each element in the vector
    mcl::Fp12 f1, f2;

    // Two Miller loops (no final exponentiation yet)
    mcl::millerLoop(f1, batch.commonG1P1.get().value,  currentG2P1.value);    // f1 = ML(g1P1, g2P1)
    mcl::millerLoop(f2, g1P2Negatted, currentG2P2.value);         // f2 = ML(-g1P2, g2P2)

    // Combine, then a single final exponentiation
    f1 *= f2;                    // f1 = ML(g1P1,g2P1) * ML(-g1P2,g2P2)
    mcl::finalExp(f1, f1);       // f1 = FE( ... )

    isValidVec[i] = f1.isOne();           // product == 1 ?
}
```


