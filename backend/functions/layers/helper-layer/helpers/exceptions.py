
class BaseCustomException(Exception):
    """Base class for all custom exceptions in this module."""
    pass


class AthenaQueryFailedException(BaseCustomException):
    """Exception raised when an Athena query fails."""
    pass


class AthenaQueryTimedOut(BaseCustomException):
    """Exception raised when an Athena query times out."""
    pass


class UnsafeAthenaQueryException(BaseCustomException):
    """Exception raised when an Athena query is considered unsafe."""
    pass
