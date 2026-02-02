"""
Core implementation of SKALE Threshold Encryption interface.
"""
import ctypes
import os
from ctypes import c_char_p

from .exceptions import EncryptionError, LibraryNotFoundError

def _load_library():
    """Finds and loads the shared library, setting up function signatures."""
    # The library is expected to be in the same directory as this file
    lib_path = os.path.join(os.path.dirname(__file__), 'libencrypt.so')

    if not os.path.exists(lib_path):
        # Fallback for development/testing if not explicitly installed
        # Check if we can find it in common build locations relative to this file
        current_dir = os.path.dirname(__file__)
        possible_paths = [
            os.path.abspath(os.path.join(current_dir, '../../build/threshold_encryption/libskale_te_python.so')),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                lib_path = path
                break

    if not os.path.exists(lib_path):
        raise LibraryNotFoundError(f"Shared library not found. Checked {lib_path} and build directories.")

    try:
        lib = ctypes.CDLL(lib_path)
    except OSError as e:
        raise LibraryNotFoundError(f"Could not load shared library at {lib_path}: {e}") from e

    # Define return types and argument types for C++ functions
    lib.encryptMessage.restype = c_char_p
    lib.encryptMessage.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

    lib.encryptMessageDualKey.restype = c_char_p
    lib.encryptMessageDualKey.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p]

    lib.encryptMessageMockup.restype = c_char_p
    lib.encryptMessageMockup.argtypes = [c_char_p]

    return lib


# Load the shared library
_lib = _load_library()

def encrypt_message(
        tx_data: str,
        public_key: str,
        additional_authenticated_data_aes: str | None = None,
        additional_authenticated_data_te: str | None = None) -> str:
    """
    Encrypts a message using a single BLS public key.

    Args:
        tx_data (str): The transaction data hex string.
        public_key (str): The BLS public key hex string.
        additional_authenticated_data_aes (str | None, optional): AES additional authenticated data.
        additional_authenticated_data_te (str | None, optional): TE additional authenticated data.

    Returns:
        str: The encrypted message as a hex string.

    Raises:
        ValueError: If tx_data or public_key are empty.
        EncryptionError: If encryption fails.
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
        raise EncryptionError("Encryption failed. Check library logs for details.")
    return result.decode('utf-8')

def encrypt_message_dual_key(
        tx_data: str,
        first_key: str,
        second_key: str,
        additional_authenticated_data_aes: str | None = None,
        additional_authenticated_data_te: str | None = None) -> str:
    """
    Encrypts a message using two BLS public keys (dual-key encryption).
    Args:
        tx_data (str): The transaction data hex string to be encrypted.
        first_key (str): The first BLS public key hex string.
        second_key (str): The second BLS public key hex string.
        additional_authenticated_data_aes (str | None, optional): AES additional authenticated data.
        additional_authenticated_data_te (str | None, optional): TE additional authenticated data.
    Returns:
        str: The encrypted message as a hex string produced by dual-key encryption.

    Raises:
        ValueError: If tx_data, first_key, or second_key are empty.
        EncryptionError: If dual key encryption fails.
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
        raise EncryptionError("Dual key encryption failed. Check library logs for details.")
    return result.decode('utf-8')

def encrypt_message_mockup(tx_data: str) -> str:
    """
    Mockup encryption for testing purposes.
    Args:
        tx_data (str): The transaction data hex string.
    Returns:
        str: The mockup encrypted message as a hex string.

    Raises:
        ValueError: If tx_data is empty.
        EncryptionError: If mockup encryption fails.
    """
    if not tx_data:
        raise ValueError("tx_data must not be empty")

    result = _lib.encryptMessageMockup(tx_data.encode('utf-8'))
    if result is None:
        raise EncryptionError("Mockup encryption failed. Check library logs for details.")
    return result.decode('utf-8')
