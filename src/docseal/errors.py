class ImageEncryptorError(Exception):
    """Base error for DocSeal CLI."""


class InvalidFormatError(ImageEncryptorError):
    """Raised when input file format/header is invalid."""


class DecryptionError(ImageEncryptorError):
    """Raised when decryption fails (wrong password or tampered data)."""


class FileTooLargeError(ImageEncryptorError):
    """Raised when file size exceeds the configured limit."""


class UnsafeOperationError(ImageEncryptorError):
    """Raised when a safety precondition is not met (e.g., delete confirmation)."""
