"""
Exceptions raised by the aquasec library.

The library never calls ``sys.exit()``. A failure is raised as one of these so
the host application decides what happens next -- a CLI can print the message
and exit, a service can log it and carry on. Every class derives from
``AquaError``, so ``except AquaError`` catches anything the library raises on
purpose.
"""


class AquaError(Exception):
    """Base class for every error the aquasec library raises deliberately.

    ``status_code`` and ``response_text`` are set when the error came from an
    HTTP response, and are None otherwise.
    """

    def __init__(self, message, status_code=None, response_text=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class AuthenticationError(AquaError):
    """Signing in failed: the platform rejected the credentials or the request."""


class MissingCredentialsError(AuthenticationError):
    """``authenticate()`` found no usable set of ``AQUA_*`` environment variables."""


class ApiError(AquaError):
    """An API call returned a response the library could not handle."""
