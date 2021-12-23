"""Keycloak API Client for integrating authentication and authorization with FastAPI"""

__version__ = "0.0.1"

from fastapi_keycloak.api import FastAPIKeycloak
from fastapi_keycloak.model import OIDCUser, UsernamePassword, HTTPMethod, KeycloakError, KeycloakUser, KeycloakToken, KeycloakRole, KeycloakIdentityProvider

__all__ = [FastAPIKeycloak.__name__, OIDCUser.__name__, UsernamePassword.__name__, HTTPMethod.__name__, KeycloakError.__name__, KeycloakUser.__name__, KeycloakToken.__name__,
           KeycloakRole.__name__, KeycloakIdentityProvider.__name__]
