class TEncryptError(Exception):
    """Base exception for t-encrypt errors."""
    pass

class LibraryNotFoundError(TEncryptError):
    """Raised when the shared library cannot be found or loaded."""
    pass

class EncryptionError(TEncryptError):
    """Raised when encryption fails."""
    pass
