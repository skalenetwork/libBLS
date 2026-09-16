#!/usr/bin/env python3
"""
Simple functional test for the installed t_encrypt package.

Exercises the real consumer boundary (Python -> ctypes -> libencrypt.so)

encrypt_message / encrypt_message_dual_key require a valid BLS common
public key hex string.
"""

from t_encrypt import encrypt_message, encrypt_message_dual_key, encrypt_message_mockup

SAMPLE_TX_HEX = "deadbeef"

# Fixed BLS common public key used for encryption tests. Generated once via
# the `generate_bls_keys` tool - there's no need to regenerate it on every
# run since only t_encrypt's encryption logic is under test here.
DEFAULT_PUBLIC_KEY = (
    "092e706a6cd636f555261b5fe3d52072b00d8ccb94357f1766620bbf5ceee78"
    "a1e7f735264da6df4a067441a07de7b8af125888060bf6918f32a7ad7155491"
    "e60812921d666125f7432a04510c667efbec95456fb66390b1b01b4271385a9"
    "99601c485b3f92bf2a305ac0dbe58bf21dc5a6b74ca5411bc8df9e5cc9a41ee"
    "bba7"
)


def is_hex(value: str) -> bool:
    return bool(value) and all(c in "0123456789abcdefABCDEF" for c in value)


def test_encrypt_message_mockup():
    result = encrypt_message_mockup(SAMPLE_TX_HEX)
    assert is_hex(result), f"encrypt_message_mockup returned non-hex: {result!r}"
    print("encrypt_message_mockup: OK")


def test_encrypt_message():
    result = encrypt_message(SAMPLE_TX_HEX, DEFAULT_PUBLIC_KEY)
    assert is_hex(result), f"encrypt_message returned non-hex: {result!r}"
    print("encrypt_message: OK")


def test_encrypt_message_dual_key():
    result = encrypt_message_dual_key(SAMPLE_TX_HEX, DEFAULT_PUBLIC_KEY, DEFAULT_PUBLIC_KEY)
    assert is_hex(result), f"encrypt_message_dual_key returned non-hex: {result!r}"
    print("encrypt_message_dual_key: OK")


def main():
    test_encrypt_message_mockup()
    test_encrypt_message()
    test_encrypt_message_dual_key()


if __name__ == "__main__":
    main()
