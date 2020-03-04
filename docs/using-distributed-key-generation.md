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

When created dkg_obj generates secret polynomial, but if you want you can set your own one with the method \_setDKGSecret_

3.  Each participant generates a vector of public shares coefficients and broadcasts it.

For BLS

```cpp
std::shared_ptr < std::vector <libff::alt_bn128_G2>>  public_shares = dkg_obj.createDKGPublicShares();
```

For TE

```cpp
std::shared_ptr <std::vector <encryption::element_wrapper>>  public_shares =
                                                                      dkg_obj.createDKGPublicShares();
```

4.  Each participant generates vector of secret shares coefficients. And sends to j-th participant j-th component of secret shares coefficients vector. ( j = 1 .. n and not equal to current participant index).

For BLS

```cpp
std::shared_ptr <std::vector <libff::alt_bn128_Fr>>  private_shares = dkg_obj.createDKGSecretShares();
```

For TE

```cpp
std::shared_ptr < std::vector <encryption::element_wrapper>>  private_shares =
                                                                       dkg_obj.createDKGSecretShares();
```

5.  Each participant verifies that for data recieved other participants  secret share matches vector of public shares

```cpp
assert(dkg_obj. VerifyDKGShare( signerIndex, secret_share, public_shares_vector));
```

where public_shares_vector is shared_ptr to vector of public shares, signerIndex is index of participant from which secret and public shares were recieved.

6.  If verification passed each participant may create private key from secret shares that it received

For BLS

```cpp
BLSPrivateKeyShare privateKeyShare = dkg_obj.CreateBLSPrivateKeyShare(secret_shares_vector);
```

For TE

```cpp
TEPrivateKeyShare privateKeyShare = dkg_obj.CreateTEPrivateKeyShare(secret_shares_vector);
```

Also in DKGTEWrapper there is a static function that creates common public key

```cpp
TEPublicKey publicKey = DKGTEWrapper::CreateTEPublicKey( public_shares_all, t, n);
```

where public_shares_all is shared_ptr to matrix of all public shares ( its type is std::shared_ptr&lt;std::vector&lt;std::vector&lt;encryption::element_wrapper>>>).

Here is an example of Threshold Encryption algorithm with DKG simulation for t = 3, n = 4.

```cpp
size_t num_signed = 3;
size_t num_all = 4;
std::vector<std::vector<encryption::element_wrapper>> secret_shares_all; // matrix of all secret shares
std::vector<std::vector<encryption::element_wrapper>> public_shares_all; //// matrix of all public shares
std::vector<DKGTEWrapper> dkgs; // instances of DKGTEWrapper for each participant
std::vector<TEPrivateKeyShare> skeys; // private keys of participants
std::vector<TEPublicKeyShare> pkeys;  // public keys of participants

for (size_t i = 0; i < num_all; i++) {
  DKGTEWrapper dkg_wrap(num_signed, num_all);
  dkgs.push_back(dkg_wrap);

  // create secret shares for each participant
  std::shared_ptr<std::vector<encryption::element_wrapper>> secret_shares_ptr =
                                                                      dkg_wrap.createDKGSecretShares();

 // create public shares for each participant
 std::shared_ptr<std::vector<encryption::element_wrapper>> public_shares_ptr =
                                                                      dkg_wrap.createDKGPublicShares();

 secret_shares_all.push_back(*secret_shares_ptr);
 public_shares_all.push_back(*public_shares_ptr);
}

for (size_t i = 0; i < num_all; i++)      // Verifying shares for each participant
 for (size_t j = 0; j < num_all; j++) {
   assert(dkgs.at(i).VerifyDKGShare(j, secret_shares_all.at(i).at(j),
                    std::make_shared<std::vector<encryption::element_wrapper>>(public_shares_all.at(i))));
 }
 std::vector<std::vector<encryption::element_wrapper>> secret_key_shares;

 for (size_t i = 0; i < num_all; i++) {          // collect got secret shares in a vector
   std::vector<encryption::element_wrapper> secret_key_contribution;
   for (size_t j = 0; j < num_all; j++) {
     secret_key_contribution.push_back(secret_shares_all.at(j).at(i));
   }
   secret_key_shares.push_back(secret_key_contribution);
 }

 for (size_t i = 0; i < num_all; i++) {
   TEPrivateKeyShare pkey_share = dkgs.at(i).CreateTEPrivateKeyShare(
                                             i + 1,
                                             std::make_shared<std::vector<encryption::element_wrapper>>(
                                                                              secret_key_shares.at(i)));
   skeys.push_back(pkey_share);
   pkeys.push_back(TEPublicKeyShare(pkey_share, num_signed, num_all));
 }

 TEPublicKey common_public = DKGTEWrapper::CreateTEPublicKey(
             std::make_shared< std::vector<std::vector<encryption::element_wrapper>>>(public_shares_all),
             num_signed,
             num_all);

 std::string message;    // Generating random message
 size_t msg_length = 64;
 for (size_t length = 0; length < msg_length; ++length) {
   message += char(rand_gen() % 128);
 }

 std::shared_ptr msg_ptr = std::make_shared<std::string>(message);
 encryption::Ciphertext cypher = common_public.encrypt(msg_ptr);

// removing 1 random participant ( because only 3 of 4 will participate)
 size_t ind4del = rand_gen() % secret_shares_all.size();
 auto pos4del = secret_shares_all.begin();
 advance(pos4del, ind4del);
 secret_shares_all.erase(pos4del);
 auto pos2 = public_shares_all.begin();
 advance(pos2, ind4del);
 public_shares_all.erase(pos2);

 TEDecryptSet decr_set(num_signed, num_all);
 for (size_t i = 0; i < num_signed; i++) {
   encryption::element_wrapper decrypt = skeys.at(i).decrypt(cypher);
   assert(pkeys.at(i).Verify(cypher, decrypt.el_));
   std::shared_ptr decr_ptr = std::make_shared<encryption::element_wrapper>(decrypt);
   decr_set.addDecrypt(skeys.at(i).getSignerIndex(), decr_ptr);
 }

 std::string message_decrypted = decr_set.merge(cypher);
}
```
