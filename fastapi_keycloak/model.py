from enum import Enum
from typing import List

from pydantic import BaseModel, SecretStr


class BadRequest(BaseModel):
    """ Represents a failed request with its content as reason payload """
    reason: str
    status_code: int


class HTTPMethod(Enum):
    """ Represents the basic HTTP verbs """
    GET = 'get'
    POST = 'post'
    DELETE = 'delete'
    PUT = 'put'


class KeycloakUser(BaseModel):
    """ Represents a user object of Keycloak """
    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: str
    lastName: str
    email: str
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    notBefore: int
    access: dict


class UsernamePassword(BaseModel):
    """ Represents a request body that contains username and password """
    username: str
    password: SecretStr


class OIDCUser(BaseModel):
    """ Represents a user object of Keycloak, parsed from an access token """
    sub: str
    iat: int
    exp: int
    scope: str
    email_verified: bool
    name: str
    given_name: str
    family_name: str
    email: str
    realm_access: dict

    @property
    def roles(self) -> List[str]:
        """ Returns the roles of the user """
        return self.realm_access.get('roles')

    def __str__(self):
        """ String representation of an OIDCUser """
        return self.email


class KeycloakIdentityProvider(BaseModel):
    """ Keycloak representation of an identity provider """
    alias: str
    internalId: str
    providerId: str
    enabled: bool
    updateProfileFirstLoginMode: str
    trustEmail: bool
    storeToken: bool
    addReadTokenRoleOnCreate: bool
    authenticateByDefault: bool
    linkOnly: bool
    firstBrokerLoginFlowAlias: str
    config: dict


class KeycloakRole(BaseModel):
    """ Keycloak representation of a role"""
    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    """ Keycloak representation of a token object """
    access_token: str

    def __str__(self):
        """ String representation of KeycloakToken """
        return f'Bearer {self.access_token}'
