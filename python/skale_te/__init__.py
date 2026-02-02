"""
This module provides a Python interface to the SKALE Threshold Encryption C++ library.
It allows encrypting messages using BLS keys.
"""
from .core import encrypt_message, encrypt_message_dual_key, encrypt_message_mockup
from .exceptions import SkaleTEError, LibraryNotFoundError, EncryptionError

__all__ = [
    'encrypt_message',
    'encrypt_message_dual_key',
    'encrypt_message_mockup',
    'SkaleTEError',
    'LibraryNotFoundError',
    'EncryptionError',
]
