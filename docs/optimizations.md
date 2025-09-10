This document describes steps taken into optimizing Elliptic Curve Algebra's performance

## Assumptions

* **Groups:**  
  - $G_1, G_2$ are cyclic subgroups of prime order $r$  
  - $G_T$ is a multiplicative group of the same order $r$  
  - All groups are defined over an extension field $\mathbb{F}_{p^k}$ for suitable $p,k$.

* **Pairing:**  
  - $e : G_1 \times G_2 \to G_T$ is a bilinear, non-degenerate, efficiently computable map  
  - Bilinearity: $e(aP,bQ) = e(P,Q)^{ab}$ for all $a,b \in \mathbb{Z}_r$

* **Notation:**  
  - $ML(P,Q)$: **Miller loop output** in $\mathbb{F}_{p^k}^{*}$ (before final exponentiation)  
  - $FE(x)$: **Final exponentiation**, $FE(x) = x^{(p^k-1)/r}$ mapping $x$ into $G_T$  
  - Equality in $G_T$: $A = B \;\Longleftrightarrow\; A \cdot B^{-1} = 1$


---

### 1. Check once, use all

- Complete ciphertext validation, including pairing computation is done only once at receival of ciphertext.
- Every call after `ThresholdEncryption::validateEncryption` assumes ciphertext was already validated by this call.
- Even so, subsequent calls can still fail if for some reason the ciphertext got tampered with (say, someone got access to computer's RAM and tampered it)

#### Result
- 2 less pairing computations on each call
- ~1.4x speedup compared to previous version

---

### 2. Optimizing Pairing Equality

#### Claim  

Instead of checking  
$$
e(P_1, Q_1) \overset{?}{=} e(P_2, Q_2)
$$  
with two full pairings (two Miller loops + two final exponentiations), we can:  

1. Run two **Miller loops**:  
   $$
   f_1 = ML(P_1, Q_1), \qquad f_2 = ML(-P_2, Q_2)
   $$
2. Multiply in the extension field:  
   $$
   f = f_1 \cdot f_2
   $$
3. Perform a **single** final exponentiation and check  
   $$
   FE(f) \overset{?}{=} 1
   $$

#### Proof  

1. **Equality via inverse in $G_T$**  
   In any group $G$,  
   $$
   A = B \quad \Longleftrightarrow \quad A \cdot B^{-1} = 1.
   $$
   Hence  
   $$
   e(P_1,Q_1) = e(P_2,Q_2)
   \quad \Longleftrightarrow \quad
   e(P_1,Q_1)\,e(P_2,Q_2)^{-1} = 1.
   $$

2. **Bilinearity gives inversion via negation**  
   Since  
   $$
   e(aP,Q) = e(P,Q)^a,
   $$
   we have in particular  
   $$
   e(-P_2,Q_2) = e(P_2,Q_2)^{-1}.
   $$

3. **Miller outputs before final exponentiation**  
   The Miller loop $ML(P,Q)$ returns an element $f \in \mathbb{F}_{q^k}^{*}$ such that  
   $$
   FE(f) = f^{(q^k-1)/r} = e(P,Q).
   $$
   So with  
   $$
   f_1 = ML(P_1,Q_1), \qquad f_2 = ML(-P_2,Q_2),
   $$
   we have  
   $$
   FE(f_1) = e(P_1,Q_1), \qquad FE(f_2) = e(-P_2,Q_2).
   $$

4. **Final exponentiation is a homomorphism**  
   For $x,y \in \mathbb{F}_{q^k}^{*}$,  
   $$
   FE(xy) = (xy)^{k} = x^{k}\,y^{k} = FE(x)\,FE(y).
   $$

5. **Combine results**  
   We multiply the Miller outputs and apply $FE$ once:  
   $$
   FE(f_1 \cdot f_2) = FE(f_1)\cdot FE(f_2)
   = e(P_1,Q_1)\cdot e(-P_2,Q_2)
   = e(P_1,Q_1)\cdot e(P_2,Q_2)^{-1}.
   $$
   Therefore  
   $$
   e(P_1,Q_1) = e(P_2,Q_2)
   \quad \Longleftrightarrow \quad
   FE(f_1 \cdot f_2) = 1.
   $$

#### Conclusion  

Two Miller loops followed by one final exponentiation is **algebraically equivalent** to two full pairings but costs only **one** final exponentiation instead of two, making it strictly cheaper in practice.


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
mcl::millerLoop(f1, g1P1.value,  g2P1.value);    // f1 = `ML(g1P1, g2P1)`
G1BackendType g1P2Negatted = g1P2.value;
G1BackendType::neg(g1P2Negatted, g1P2.value);  // -g1P2
mcl::millerLoop(f2, g1P2Negatted, g2P2.value);         // f2 = `ML(-g1P2, g2P2)`

// Combine, then a single final exponentiation
f1 *= f2;                    // f1 = `ML(g1P1,g2P1)` * `ML(-g1P2,g2P2)`
mcl::finalExp(f1, f1);       // f1 = `FE( ... )`

return f1.isOne();           // product == 1 ?
```

---

### 3. Caching common terms using batches

A batch of decrpyion shares must be validated using the test $ e(P_1^i,Q_1^i) \overset{?}{=} e(P_2^i,Q_2^i) $ for i=1..n.
Both $P_1^i$ and $P_2^i$ are derived from the same common ciphertext. This is an invariant in the loop, thus $P_1^i$ and $P_2^i$ are always the same for any $i$.
We can thus compute negation of $P_2^{neg} = -P_2 $ only once, and reuse it over the entire batch.

---

### 4. Optimistic Batched Validation

We want to verify $N$ pairing equations

$$
e(P_1, Q_{1,i}) = e(P_2, Q_{2,i}) \qquad \text{for all } i = 1, \dots, N
$$

Note that $ P_1 $ and $ P_2 $ **always have the same value** idependently of $i$. This is because, all shares within the same batch refer to the same ciphertext - from which both $ P_1 $ and $ P_2 $ are derived from exactly in the same deterministic way independently of the specific share.


#### Claim

Pick independent random scalars $r_i \in_R \mathbb{Z}_r^{*}$ and form a single *aggregated equation*

$$
e\left( P_1, \sum_{i=1}^N r_i \cdot Q_{1,i} \right) \cdot
e\left( P_2, \sum_{i=1}^N r_i \cdot Q_{2,i} \right)^{-1} = 1.
$$

This check passes iff each share is valid, i.e, if for all $i$:
$$
e(P_{1,i}, Q_{1, i}) = e(P_{2,i}, Q_{2, i})
$$

And fails if at least 1 of the checks fails.
False negatives can only happen with probability $ \frac{1}{r} $, which is negligeable.


#### Proof
- **Completeness (no false negatives).**  
  If $\forall i:\ e(P_1,Q_{1,i})=e(P_2,Q_{2,i})$, then by bilinearity,
  $$
  e\!\left(P_1,\sum_i r_i Q_{1,i}\right)
  = \prod_i e(P_1,Q_{1,i})^{r_i}
  = \prod_i e(P_2,Q_{2,i})^{r_i}
  = e\!\left(P_2,\sum_i r_i Q_{2,i}\right),
  $$
  so the aggregated check equals $1$.

- **Soundness (high-probability detection of any error).**  
  If there exists $j$ with $e(P_1,Q_{1,j})\neq e(P_2,Q_{2,j})$, define
  $$
  Z \;=\; \prod_{i=1}^N \big(e(P_1,Q_{1,i})\,e(P_2,Q_{2,i})^{-1}\big)^{r_i}\ \in G_T\setminus\{1\}
  $$
  except with probability at most $1/r$ over random $(r_i)$.  
  Thus the batch fails with probability $\ge 1-1/r$, which is negligible.


#### Implementation notes (one final exponentiation)
Compute two Miller loops, multiply, then perform a **single** final exponentiation:
$$
F \;=\; \mathrm{ML}\!\left(P_1,\sum_i r_i Q_{1,i}\right)\cdot
         \mathrm{ML}\!\left(P_2,\sum_i r_i Q_{2,i}\right)^{-1},
\qquad
F^{(q^k-1)/r}\stackrel{?}{=}1.
$$


#### Preconditions (to preserve the proof assumptions)
- $r_i$ drawn uniformly from $\mathbb{Z}_r^{*}$ and fresh per batch.
- Inputs validated in the correct prime-order subgroups (or cofactor cleared).
- $P_1\in G_1$, $P_2\in G_1$, $Q_{1,i},Q_{2,i}\in G_2$.


