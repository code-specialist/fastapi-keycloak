from fastapi import HTTPException


class KeycloakError(Exception):
    """ Thrown if any response of keycloak does not match our expectation

    Attributes:
        status_code (int): The status code of the response received
        reason (str): The reason why the requests did fail
    """

    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason
        super().__init__(f'HTTP {status_code}: {reason}')


class MandatoryActionException(HTTPException):
    """ Throw if the exchange of username and password for an access token fails """
    def __init__(self, detail: str) -> None:
        super().__init__(status_code=400, detail=detail)


class UpdateUserLocaleException(MandatoryActionException):
    """ Throw if the exchange of username and password for an access token fails due to the update_user_locale
    requiredAction """
    def __init__(self) -> None:
        super().__init__(detail="This user can't login until he updated his locale")


class ConfigureTOTPException(MandatoryActionException):
    """ Throw if the exchange of username and password for an access token fails due to the CONFIGURE_TOTP
    requiredAction """
    def __init__(self) -> None:
        super().__init__(detail="This user can't login until he configured TOTP")


class VerifyEmailException(MandatoryActionException):
    """ Throw if the exchange of username and password for an access token fails due to the VERIFY_EMAIL
    requiredAction """
    def __init__(self) -> None:
        super().__init__(detail="This user can't login until he verified his email")


class UpdatePasswordException(MandatoryActionException):
    """ Throw if the exchange of username and password for an access token fails due to the UPDATE_PASSWORD
    requiredAction """
    def __init__(self) -> None:
        super().__init__(detail="This user can't login until he updated his password")


class UpdateProfileException(MandatoryActionException):
    """ Throw if the exchange of username and password for an access token fails due to the UPDATE_PROFILE
    requiredAction """
    def __init__(self) -> None:
        super().__init__(detail="This user can't login until he updated his profile")
