from enum import Enum
from typing import List

from pydantic import BaseModel, SecretStr

from fastapi_keycloak.exceptions import KeycloakError


class HTTPMethod(Enum):
    """ Represents the basic HTTP verbs

    Values:
        - GET: get
        - POST: post
        - DELETE: delete
        - PUT: put
    """
    GET = 'get'
    POST = 'post'
    DELETE = 'delete'
    PUT = 'put'


class KeycloakUser(BaseModel):
    """ Represents a user object of Keycloak.
    
    Attributes:
        id (str):
        createdTimestamp (int):
        username (str):
        enabled (bool):
        totp (bool):
        emailVerified (bool):
        firstName (str):
        lastName (str):
        email (str):
        disableableCredentialTypes (List[str]):
        requiredActions (List[str]):
        notBefore (int):
        access (dict):

    Notes:
         Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for details. This is a mere proxy object.
    """
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
    """ Represents a request body that contains username and password

    Attributes:
        username (str): Username
        password (str): Password, masked by swagger
    """
    username: str
    password: SecretStr


class OIDCUser(BaseModel):
    """ Represents a user object of Keycloak, parsed from an access token 
    
    Attributes:
        sub (str):
        iat (int):
        exp (int):
        scope (str):
        email_verified (bool):
        name (str):
        given_name (str):
        family_name (str):
        email (str):
        realm_access (dict):

    Notes:
         Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for details. This is a mere proxy object.
    """
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
        """ Returns the roles of the user

        Returns:
            List[str]: If the realm access dict contains roles
        """
        try:
            return self.realm_access['roles']
        except KeyError:
            raise KeycloakError(status_code=404, reason="The 'realm_access' section of the provided access token did not contain any 'roles'")

    def __str__(self) -> str:
        """ String representation of an OIDCUser """
        return self.email


class KeycloakIdentityProvider(BaseModel):
    """ Keycloak representation of an identity provider

    Attributes:
        alias (str):
        internalId (str):
        providerId (str):
        enabled (bool):
        updateProfileFirstLoginMode (str):
        trustEmail (bool):
        storeToken (bool):
        addReadTokenRoleOnCreate (bool):
        authenticateByDefault (bool):
        linkOnly (bool):
        firstBrokerLoginFlowAlias (str):
        config (dict):

    Notes:
        Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for details. This is a mere proxy object.
    """
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
    """ Keycloak representation of a role
    
    Attributes:
        id (str):
        name (str):
        composite (bool):
        clientRole (bool):
        containerId (str):
        
    Notes:
        Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for details. This is a mere proxy object.
    """
    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    """ Keycloak representation of a token object

    Attributes:
        access_token (str): An access token
    """
    access_token: str

    def __str__(self):
        """ String representation of KeycloakToken """
        return f'Bearer {self.access_token}'
