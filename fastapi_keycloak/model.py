from enum import Enum
from typing import List

from pydantic import BaseModel, SecretStr


class BadRequest(BaseModel):
    reason: str
    status_code: int


class HTTPMethod(Enum):
    GET = 'get'
    POST = 'post'
    DELETE = 'delete'
    PUT = 'put'


class KeycloakUser(BaseModel):
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
    username: str
    password: SecretStr


class OIDCUser(BaseModel):
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
        return self.realm_access.get('roles')

    def __str__(self):
        return self.email


class KeycloakIdentityProvider(BaseModel):
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
    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    access_token: str

    def __str__(self):
        return f'Bearer {self.access_token}'
