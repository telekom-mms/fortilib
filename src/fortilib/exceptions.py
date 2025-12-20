import httpx


class APIException(Exception):
    """Fortigate Base API Exception extends :py:class:`Exception`."""

    def __init__(self, response: httpx.Response) -> None:
        self.response = response
        super().__init__(self.message())

    def message(self):
        """Return formatted exception message with response code and detailed error description."""
        forti_error_msg: str = self.response.text
        if "cli_error" in forti_error_msg:
            forti_error_msg = self.response.json()["cli_error"]
        return repr(
            f"Response Code: {self.response.status_code} - "
            f"{forti_error_msg}"
        )


class BadRequestExeption(APIException):
    pass


class NotAuthorizedException(APIException):
    pass


class ForbiddenException(APIException):
    pass


class ResourceNotFoundException(APIException):
    pass


class MethodNotAllowedException(APIException):
    pass


class RequestEntityTooLargeException(APIException):
    pass


class FailedDependencyException(APIException):
    pass


class TooManyRequestsException(APIException):
    pass


class InternalErrorException(APIException):
    pass


class FortilibException(Exception):
    pass


class ObjectAlreadyExitsException(FortilibException):
    pass


class InterfaceMismatchException(FortilibException):
    pass


class AddressTypeMismatchException(FortilibException):
    pass
