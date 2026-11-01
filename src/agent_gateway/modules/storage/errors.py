"""Storage failures. None of these carry file contents in their messages."""


class StorageError(Exception):
    """A storage operation failed."""


class CorruptCollectionError(StorageError):
    """A collection file exists but cannot be parsed or fails validation."""


class SchemaVersionError(StorageError):
    """A collection file has a schema version this build cannot read (SPEC §6.2)."""


class LockTimeoutError(StorageError):
    """A cross-process lock could not be acquired in time."""


class InvalidNameError(StorageError, ValueError):
    """A lock or blob name is not a safe single path component."""
