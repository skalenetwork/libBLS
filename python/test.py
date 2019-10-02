#!/usr/bin/env python3
# encoding: utf-8

import dkgpython
from dkgpython import dkg

import os
import sys
import binascii
import json
import logging
import coincurve

from time import sleep

def bxor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def encrypt(plaintext, secret_key):
    plaintext_in_bytes = bytearray(int(plaintext).to_bytes(32, byteorder ='big'))
    return bxor(plaintext_in_bytes, secret_key)

def decrypt(ciphertext, secret_key):
    xor_val = bxor(ciphertext, secret_key)
    ret_val = binascii.hexlify(xor_val)
    return str(int(ret_val.decode(), 16))

def convert_g2_point_to_bytes(data):
    data_hexed = "0x"
    for coord in data:
        for elem in coord:
            temp = hex(int(elem[0]))[2:]
            while (len(temp) < 64):
                temp = '0' + temp
            data_hexed += temp
            temp = hex(int(elem[1]))[2:]
            while len(temp) < 64 :
                temp = '0' + temp
            data_hexed += temp
    return data_hexed

class DkgVerificationError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class DKGClient:
    def __init__(self, node_id, wallet, t, n, public_keys):
        self.node_id = node_id
        self.wallet = wallet
        self.t = t
        self.n = n
        self.dkg_instance = dkg(t, n)
        self.incoming_verification_vector = ['0'] * n
        self.incoming_secret_key_contribution = ['0'] * n
        self.public_keys = public_keys
        self.disposable_keys = ['0'] * n
        self.ecdh_keys = ['0'] * n

    def GeneratePolynomial(self):
        return self.dkg_instance.GeneratePolynomial()

    def VerificationVector(self, polynom):
        verification_vector = self.dkg_instance.VerificationVector(polynom)
        self.incoming_verification_vector[self.node_id] = verification_vector
        verification_vector_hexed = convert_g2_point_to_bytes(verification_vector)
        return verification_vector_hexed

    def SecretKeyContribution(self, polynom):
        self.sent_secret_key_contribution = self.dkg_instance.SecretKeyContribution(polynom)
        secret_key_contribution = self.sent_secret_key_contribution
        self.incoming_secret_key_contribution[self.node_id] = secret_key_contribution[self.node_id]
        to_broadcast = bytes('', 'utf-8')
        for i in range(self.n):
            self.disposable_keys[i] = coincurve.keys.PrivateKey(coincurve.utils.get_valid_secret())
            self.ecdh_keys[i] = self.disposable_keys[i].ecdh(self.public_keys[i].format(compressed=False))
            secret_key_contribution[i] = encrypt(secret_key_contribution[i], self.ecdh_keys[i])
            while len(secret_key_contribution[i]) < 32:
                secret_key_contribution[i] = bytes('0', 'utf-8') + secret_key_contribution[i]
            to_broadcast = to_broadcast + secret_key_contribution[i] + self.disposable_keys[i].public_key.format(compressed=False)
        return to_broadcast

    def RecieveVerificationVector(self, fromNode, vv):
        input = binascii.hexlify(vv)
        incoming_verification_vector = []
        while len(input) > 0 :
            cur = input[:64]
            input = input[64:]
            while cur[0] == '0':
                cur = cur[1:]
            incoming_verification_vector.append(str(int(cur, 16)))
        to_verify = []
        while len(incoming_verification_vector) > 0:
            smth = []
            smth.append((incoming_verification_vector[0], incoming_verification_vector[1]))
            smth.append((incoming_verification_vector[2], incoming_verification_vector[3]))
            to_verify.append(smth)
            incoming_verification_vector = incoming_verification_vector[4:]
        self.incoming_verification_vector[fromNode] = to_verify

    def RecieveSecretKeyContribution(self, fromNode, sc):
        input = sc
        incoming_secret_key_contribution = []
        sent_public_keys = []
        while len(input) > 0:
            cur = input[:97]
            input = input[97:]
            sent_public_keys.append(cur[-65:])
            cur = cur[:-65]
            incoming_secret_key_contribution.append(cur)
        ecdh_key = coincurve.keys.PrivateKey.from_hex(self.wallet["insecure_private_key"][2:]).ecdh(sent_public_keys[self.node_id])
        incoming_secret_key_contribution[self.node_id] = decrypt(incoming_secret_key_contribution[self.node_id], ecdh_key)
        self.incoming_secret_key_contribution[fromNode] = incoming_secret_key_contribution[self.node_id]

    def Verification(self, fromNode):
        return self.dkg_instance.Verification(self.node_id, self.incoming_secret_key_contribution[fromNode], self.incoming_verification_vector[fromNode])

    def SecretKeyShareCreate(self):
        self.secret_key_share = self.dkg_instance.SecretKeyShareCreate(self.incoming_secret_key_contribution)
        self.public_key = self.dkg_instance.GetPublicKeyFromSecretKey(self.secret_key_share)

local_wallet_0 = {"address": "0x7E6CE355Ca303EAe3a858c172c3cD4CeB23701bc", "insecure_private_key": "0xa15c19da241e5b1db20d8dd8ca4b5eeaee01c709b49ec57aa78c2133d3c1b3c9"}
local_wallet_1 = {"address": "0xF64ADc0A4462E30381Be09E42EB7DcB816de2803", "insecure_private_key": "0xe7af72d241d4dd77bc080ce9234d742f6b22e35b3a660e8c197517b909f63ca8"}
public_keys = [coincurve.PublicKey(bytes.fromhex("048f163316925bf2e12a30832dee812f6ff60bf872171a84d9091672dd3848be9fc0b7bd257fbb038019c41f055e81736d8116b83e9ac59a1407aa6ea804ec88a8")), coincurve.PublicKey(bytes.fromhex("04307654b2716eb09f01f33115173867611d403424586357226515ae6a92774b10d168ab741e8f7650116d0677fddc1aea8dc86a00747e7224d2bf36e0ea3dd62c"))]


fst = DKGClient(0, local_wallet_0, 1, 2, public_keys)
snd = DKGClient(1, local_wallet_1, 1, 2, public_keys)

fst_polynomial = fst.GeneratePolynomial()
snd_polynomial = snd.GeneratePolynomial()

fst_vv = fst.VerificationVector(fst_polynomial)
snd_vv = snd.VerificationVector(snd_polynomial)

fst_sc = fst.SecretKeyContribution(fst_polynomial)
snd_sc = snd.SecretKeyContribution(snd_polynomial)

fst_received_vv = fst.RecieveVerificationVector(1, bytes.fromhex(snd_vv[2:]))
snd_received_vv = snd.RecieveVerificationVector(0, bytes.fromhex(fst_vv[2:]))

fst_received_sc = fst.RecieveSecretKeyContribution(1, snd_sc)
snd_received_sc = snd.RecieveSecretKeyContribution(0, fst_sc)

assert(fst.Verification(1))
assert(snd.Verification(0))
