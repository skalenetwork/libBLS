class SkaleTEError(Exception):
    """Base exception for skale_te errors."""
    pass

class LibraryNotFoundError(SkaleTEError):
    """Raised when the shared library cannot be found or loaded."""
    pass

class EncryptionError(SkaleTEError):
    """Raised when encryption fails."""
    pass
