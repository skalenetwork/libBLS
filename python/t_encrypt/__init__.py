"""
This module provides a Python interface to the t-encrypt C++ library.
It allows encrypting messages using BLS keys.
"""
from .core import encrypt_message, encrypt_message_dual_key, encrypt_message_mockup
from .exceptions import TEncryptError, LibraryNotFoundError, EncryptionError

__all__ = [
    'encrypt_message',
    'encrypt_message_dual_key',
    'encrypt_message_mockup',
    'TEncryptError',
    'LibraryNotFoundError',
    'EncryptionError',
]
