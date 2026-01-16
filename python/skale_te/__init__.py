"""
This module provides a Python interface to the SKALE Threshold Encryption C++ library.
It allows encrypting messages using BLS keys.
"""
import ctypes
import os
from ctypes import c_char_p

# Load the shared library
# The library is expected to be in the same directory as this file
_lib_path = os.path.join(os.path.dirname(__file__), 'libencrypt.so')

if not os.path.exists(_lib_path):
    # Fallback for development/testing if not explicitly installed
    # Check if we can find it in common build locations relative to this file
    _current_dir = os.path.dirname(__file__)
    _possible_paths = [
        os.path.abspath(os.path.join(_current_dir, '../../build/libskale_te_python.so')),
        os.path.abspath(os.path.join(_current_dir, '../../../build/libskale_te_python.so')),
        os.path.abspath(os.path.join(_current_dir, '../../build/lib/libskale_te_python.so')),
    ]
    for path in _possible_paths:
        if os.path.exists(path):
            _lib_path = path
            break

if not os.path.exists(_lib_path):
    raise FileNotFoundError(f"Shared library not found. Checked {_lib_path} and build directories.")

try:
    _lib = ctypes.CDLL(_lib_path)
except OSError as e:
    raise OSError(f"Could not load shared library at {_lib_path}: {e}") from e

# Define return types and argument types for C++ functions
_lib.encryptMessage.restype = c_char_p
_lib.encryptMessage.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

_lib.encryptMessageDualKey.restype = c_char_p
_lib.encryptMessageDualKey.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]

_lib.encryptMessageMockup.restype = c_char_p
_lib.encryptMessageMockup.argtypes = [c_char_p]

def encrypt_message(
        tx_data: str,
        public_key: str,
        additional_authenticated_data_aes: str = None,
        additional_authenticated_data_te: str = None) -> str:
    """
    Encrypts a message using a single BLS public key.

    Args:
        tx_data (str): The transaction data hex string.
        public_key (str): The BLS public key hex string.
        additional_authenticated_data_aes (str, optional): AES additional authenticated data.
        additional_authenticated_data_te (str, optional): TE additional authenticated data.

    Returns:
        str: The encrypted message as a hex string.
    """
    if not tx_data or not public_key:
        raise ValueError("tx_data and public_key must not be empty")

    aad_aes = None
    if additional_authenticated_data_aes:
        aad_aes = additional_authenticated_data_aes.encode('utf-8')

    aad_te = None
    if additional_authenticated_data_te:
        aad_te = additional_authenticated_data_te.encode('utf-8')

    result = _lib.encryptMessage(
        tx_data.encode('utf-8'),
        public_key.encode('utf-8'),
        aad_aes,
        aad_te
    )
    if result is None:
        raise RuntimeError("Encryption failed. Check library logs for details.")
    return result.decode('utf-8')

def encrypt_message_dual_key(
        tx_data: str,
        first_key: str,
        second_key: str,
        additional_authenticated_data_aes: str = None,
        additional_authenticated_data_te: str = None) -> str:
    """
    Encrypts a message using two BLS public keys (dual-key encryption).
    Args:
        tx_data (str): The transaction data hex string to be encrypted.
        first_key (str): The first BLS public key hex string.
        second_key (str): The second BLS public key hex string.
        additional_authenticated_data_aes (str, optional): AES additional authenticated data.
        additional_authenticated_data_te (str, optional): TE additional authenticated data.
    Returns:
        str: The encrypted message as a hex string produced by dual-key encryption.
    """
    if not tx_data or not first_key or not second_key:
        raise ValueError("tx_data, first_key, and second_key must not be empty")

    aad_aes = None
    if additional_authenticated_data_aes:
        aad_aes = additional_authenticated_data_aes.encode('utf-8')

    aad_te = None
    if additional_authenticated_data_te:
        aad_te = additional_authenticated_data_te.encode('utf-8')

    result = _lib.encryptMessageDualKey(
        tx_data.encode('utf-8'),
        first_key.encode('utf-8'),
        second_key.encode('utf-8'),
        aad_aes,
        aad_te
    )
    if result is None:
        raise RuntimeError("Dual key encryption failed. Check library logs for details.")
    return result.decode('utf-8')

def encrypt_message_mockup(tx_data: str) -> str:
    """
    Mockup encryption for testing purposes.
    Args:
        tx_data (str): The transaction data hex string.
    Returns:
        str: The mockup encrypted message as a hex string.
    """
    if not tx_data:
        raise ValueError("tx_data must not be empty")

    result = _lib.encryptMessageMockup(tx_data.encode('utf-8'))
    if result is None:
        raise RuntimeError("Mockup encryption failed. Check library logs for details.")
    return result.decode('utf-8')

__all__ = ['encrypt_message', 'encrypt_message_dual_key', 'encrypt_message_mockup']
