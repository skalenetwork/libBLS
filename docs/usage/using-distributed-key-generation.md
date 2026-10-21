# [DKG](https://doi.org/10.1007%2F3-540-48910-X_21) algorithm for BLS threshold signatures and Threshold Encryption

<!-- SPDX-License-Identifier: (AGPL-3.0-only OR CC-BY-4.0) -->

1.  Choose total number of participants in your group (n), give index to each participant and choose a threshold number (t) for your case. (t &lt;= n).

2.  Each participant of DKG creates an instance of dkg class with parameters t and n;
    For BLS

```cpp
DKGBLSWrapper dkg_obj(t, n);
```

For TE

```cpp
DKGTEWrapper dkg_obj(t, n);
```

When created, `dkg_obj` generates a random secret polynomial. To supply a polynomial instead, use `setDKGSecret`.

3.  Each participant generates a vector of public shares coefficients and broadcasts it.

For BLS

```cpp
std::shared_ptr < std::vector <libBLS::algebra::G2Point>> public_shares =
  dkg_obj.createDKGPublicShares();
```

For TE

```cpp
std::shared_ptr <std::vector <libBLS::algebra::G2Point>> public_shares =
  dkg_obj.createDKGPublicShares();
```

4.  Each participant generates vector of secret shares coefficients. And sends to j-th participant j-th component of secret shares coefficients vector. ( j = 1 .. n and not equal to current participant index).

For BLS

```cpp
std::shared_ptr <std::vector <libBLS::algebra::FrScalar>> private_shares =
  dkg_obj.createDKGSecretShares();
```

For TE

```cpp
std::shared_ptr < std::vector < libBLS::algebra::FrScalar >> private_shares =
  dkg_obj.createDKGSecretShares();
```

5.  Each participant verifies that for data received other participants  secret share matches vector of public shares

```cpp
bool valid = dkg_obj.VerifyDKGShare(
    participant_index, secret_share, public_shares_vector);
```

`public_shares_vector` is this dealer's public verification vector. `participant_index` is
zero-based (`0` through `n - 1`) and identifies the recipient of `secret_share`.

6. If every received contribution verifies, each participant can create its private key share
from those `n` contributions. Wrap the verified contributions received by one participant in a
shared pointer before calling the wrapper:

For BLS

```cpp
auto received_contributions = std::make_shared<
    std::vector<libBLS::algebra::FrScalar>>(secret_shares_vector);
libBLS::BLSPrivateKeyShare privateKeyShare =
    dkg_obj.CreateBLSPrivateKeyShare(received_contributions);
```

For TE, `signerIndex` is the participant's one-based index (`1` through `n`):

```cpp
auto received_contributions = std::make_shared<
    std::vector<libBLS::algebra::FrScalar>>(secret_shares_vector);
libBLS::TEPrivateKeyShare privateKeyShare =
    dkg_obj.CreateTEPrivateKeyShare(signerIndex, received_contributions);
```

Each participant derives its public key share from its private key share. The common public key
is derived from the matrix of public verification vectors; no common private key needs to be
reconstructed.

For TE:

```cpp
auto public_shares_ptr = std::make_shared<
    std::vector<std::vector<libBLS::algebra::G2Point>>>(public_shares_all);
libBLS::TEPublicKey common_te_public =
    libBLS::DKGTEWrapper::CreateTEPublicKey(public_shares_ptr, t, n);
```

For BLS, sum the constant commitments (element zero) from each participant's verification vector:

```cpp
libBLS::algebra::G2Point common_bls_point = libBLS::algebra::G2Point::identity();
for (const auto& verification_vector : public_shares_all) {
    common_bls_point = common_bls_point + verification_vector.at(0);
}
libBLS::BLSPublicKey common_bls_public(common_bls_point, t, n);
```

Here is an example of Threshold Encryption algorithm with DKG simulation for t = 3, n = 4.

```cpp
size_t num_signed = 3;
size_t num_all = 4;
std::vector<std::vector<libBLS::algebra::FrScalar>> secret_shares_all;
std::vector<std::vector<libBLS::algebra::G2Point>> public_shares_all;
std::vector<DKGTEWrapper> dkgs; // instances of DKGTEWrapper for each participant
std::vector<TEPrivateKeyShare> skeys; // private keys of participants
std::vector<TEPublicKeyShare> pkeys;  // public keys of participants

for (size_t i = 0; i < num_all; i++) {
  DKGTEWrapper dkg_wrap(num_signed, num_all);
  dkgs.push_back(dkg_wrap);

  // create secret shares for each participant
  std::shared_ptr<std::vector<libBLS::algebra::FrScalar>> secret_shares_ptr =
      dkg_wrap.createDKGSecretShares();

 // create public shares for each participant
  std::shared_ptr<std::vector<libBLS::algebra::G2Point>> public_shares_ptr =
      dkg_wrap.createDKGPublicShares();

 secret_shares_all.push_back(*secret_shares_ptr);
 public_shares_all.push_back(*public_shares_ptr);
}

for (size_t i = 0; i < num_all; i++)      // Verifying shares for each participant
 for (size_t j = 0; j < num_all; j++) {
   assert(dkgs.at(j).VerifyDKGShare(j, secret_shares_all.at(i).at(j),
                    std::make_shared<std::vector<libBLS::algebra::G2Point>>(
                      public_shares_all.at(i))));
 }
 std::vector<std::vector<libBLS::algebra::FrScalar>> secret_key_shares;

 for (size_t i = 0; i < num_all; i++) {          // collect got secret shares in a vector
   std::vector<libBLS::algebra::FrScalar> secret_key_contribution;
   for (size_t j = 0; j < num_all; j++) {
     secret_key_contribution.push_back(secret_shares_all.at(j).at(i));
   }
   secret_key_shares.push_back(secret_key_contribution);
 }

 for (size_t i = 0; i < num_all; i++) {
   TEPrivateKeyShare pkey_share = dkgs.at(i).CreateTEPrivateKeyShare(
                                             i + 1,
                                             std::make_shared<std::vector<libBLS::algebra::FrScalar>>(
                                                 secret_key_shares.at(i)));
   skeys.push_back(pkey_share);
   pkeys.push_back(TEPublicKeyShare(pkey_share));
 }

 TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
             std::make_shared<
               std::vector<std::vector<libBLS::algebra::G2Point>>>(public_shares_all),
             num_signed,
             num_all);

 std::vector<uint8_t> message_bytes = {'h', 'e', 'l', 'l', 'o'};
 libBLS::Ciphertext ciphertext =
     libBLS::ThresholdEncryption::encrypt(message_bytes, common_public);
 const libBLS::CipheredKey& ciphered_key = ciphertext.keys.at(0);
 libBLS::ThresholdEncryption::validateEncryption(ciphered_key);

 // Any threshold-sized set of participants can decrypt. This example uses the first t.
 libBLS::TEDecryptSet decr_set(num_signed, num_all);
 for (size_t i = 0; i < num_signed; i++) {
     libBLS::TEDecryptionShare share =
         libBLS::ThresholdEncryption::partialDecrypt(ciphered_key, skeys.at(i));
     libBLS::ThresholdEncryption::validateDecryptionShare(
         ciphered_key, share, pkeys.at(i));
     decr_set.addValidatedDecryptShare(share);
 }

 libBLS::AES256Key aes_key =
     libBLS::ThresholdEncryption::combineValidatedShares(ciphered_key, decr_set);
 libBLS::ThresholdEncryption::validateCombinedDecryption(
     ciphertext, aes_key, common_public);
 std::vector<uint8_t> message_decrypted =
     libBLS::ThresholdEncryption::decrypt(ciphertext, aes_key);
}
```
