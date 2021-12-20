from __future__ import annotations

import functools
import json
from json import JSONDecodeError
from typing import List, Type

import requests
from fastapi import Depends, HTTPException, FastAPI
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, ExpiredSignatureError, JWTError
from pydantic import BaseModel
from requests import Response

from fastapi_keycloak.model import HTTPMethod, KeycloakUser, OIDCUser, KeycloakToken, KeycloakRole, KeycloakIdentityProvider


class ErrorResponse(BaseModel):
    content: str
    status_code: int


def result_or_error(response_model: Type[BaseModel] = None, is_list: bool = False):
    """

    Args:
        response_model (Type[BaseModel]): Object that should be returned based on the payload
        is_list (bool): True if the return value should be a list of the response model provided

    Returns:
        BaseModel or List[BaseModel]: Based on the given signature and response circumstances

    Notes:
        - Keycloak sometimes returns empty payloads but describes the error in its content (byte encoded) which is why this function checks for JSONDecode exceptions
    """

    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):

            def create_list(json: List[dict]):
                items = list()
                for entry in json:
                    items.append(response_model.parse_obj(entry))
                return items

            def create_object(json: dict):
                return response_model.parse_obj(json)

            result: Response = f(*args, **kwargs)

            if type(result) != Response:
                return result

            if result.status_code in range(100, 399):  # Successful
                if response_model is None:  # No model given

                    try:
                        return result.json()
                    except JSONDecodeError:
                        return result.content.decode('utf-8')

                else:  # Response model given
                    if is_list:
                        return create_list(result.json())
                    else:
                        return create_object(result.json())

            else:  # Not Successful, forward status code and error
                try:
                    return ErrorResponse(content=result.json(), status_code=result.status_code)

                except JSONDecodeError:
                    return ErrorResponse(content=result.content.decode('utf-8'), status_code=result.status_code)

        return wrapper

    return inner


class FastAPIKeycloak:
    """ Instance to wrap the Keycloak API with FastAPI

    Example:
        ```python
        app = FastAPI()
        idp = KeycloakFastAPI(
            app=app,
            server_url="https://auth.some-domain.com/auth",
            client_id="some-test-client",
            client_secret="some-secret",
            admin_client_secret="some-admin-cli-secret",
            realm="Test",
            callback_uri=f"http://localhost:8081/callback"
        )
        ```
    """
    _admin_token: KeycloakToken

    def __init__(self, server_url: str, client_id: str, client_secret: str, realm: str, admin_client_secret: str, callback_uri: str, app: FastAPI = None):
        """ FastAPIKeycloak constructor

        Args:
            server_url (str): The URL of the Keycloak server, with `/auth` suffix
            client_id (str): The id of the client used for users
            client_secret (str): The client secret
            realm (str): The realm (name)
            admin_client_secret (str): Secret for the `admin-cli` client
            callback_uri (str): Callback URL of the instance, used for auth flows. Must match at least one `Valid Redirect URIs` of Keycloak
            app (FastAPI): Optional FastAPI app to add the config to swagger
        """
        self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.admin_client_secret = admin_client_secret
        self.callback_uri = callback_uri
        self.config(app)
        self._get_admin_token()

    def config(self, app: FastAPI):
        """

        Args:
            app (FastAPI): Optional FastAPI app to add the config to swagger

        Returns:
            None: Inplace method
        """
        if app:
            app.swagger_ui_init_oauth = {
                "usePkceWithAuthorizationCodeGrant": True,
                "clientId": self.client_id,
                "clientSecret": self.client_secret
            }

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """ Returns the auth scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_uri)

    def get_current_user(self, required_roles: List[str] = None) -> OIDCUser:
        """ Returns the current user based on an access token in the HTTP-header. Optionally verifies roles are possessed by the user

        Args:
            required_roles List[str]: List of role names required for this endpoint

        Returns:
            OIDCUser: Decoded JWT content
        """

        def current_user(token: OAuth2PasswordBearer = Depends(self.user_auth_scheme)) -> OIDCUser:
            """ Decodes and verifies a JWT to get the current user

            Args:
                token OAuth2PasswordBearer: Access token in `Authorization` HTTP-header

            Returns:
                OIDCUser: Decoded JWT content
            """
            options = {
                "verify_signature": True,
                "verify_aud": True,
                "verify_exp": True
            }
            decoded_token: dict = jwt.decode(token, self.public_key, options=options, audience="account")
            user = OIDCUser.parse_obj(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise HTTPException(status_code=403, detail=f'Role "{role}" is required to perform this action')
            return user

        return current_user

    @functools.cached_property
    def open_id_configuration(self) -> dict:
        """ Returns Keycloaks Open ID Connect configuration

        Returns:
            dict: Open ID Configuration
        """
        response = requests.get(url=f'{self.realm_uri}/.well-known/openid-configuration')
        return response.json()

    @result_or_error
    def proxy(self, relative_path: str, method: HTTPMethod, additional_headers: dict = None, payload: dict = None) -> dict:
        """ Proxies a request to Keycloak and automatically adds the required Authorization header. Should not be exposed under any circumstances. Grants full API admin access.

        Args:

            relative_path (str): The relative path of the request. Requests will be sent to: `[server_url]/[relative_path]`
            method (HTTPMethod): The HTTP-verb to be used
            additional_headers (dict): Optional headers besides the Authorization to add to the request
            payload (dict): Optional payload to send

        Returns:
            dict: Proxied response payload
        """
        return requests.request(
            method=method.name,
            url=f'{self.server_url}{relative_path}',
            data=json.dumps(payload),
            headers={"Authorization": f"Bearer {self.admin_token}", **additional_headers}
        )

    def _get_admin_token(self):
        """ Exchanges client credentials (admin-cli) for an access token.

        Returns:
            KeycloakToken: The object that is set to _admin_token
        Notes:
            - Is executed on startup and may be executed again if the token validation fails
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "client_id": "admin-cli",
            "client_secret": self.admin_client_secret,
            "grant_type": "client_credentials"
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        self._admin_token = KeycloakToken.parse_obj(response.json())
        return self.admin_token

    @functools.cached_property
    def public_key(self) -> str:
        """ Returns the Keycloak public key

        Returns:
            str: Public key for JWT decoding
        """
        response = requests.get(url=self.realm_uri)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    @result_or_error
    def add_user_roles(self, roles: List[str], user_id: str) -> dict:
        """ Adds roles to a specific user

        Args:
            roles List[str]: Roles to add (name)
            user_id str: ID of the user the roles should be added to

        Returns:
            dict: Proxied response payload
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f'{self.users_uri}/{user_id}/role-mappings/realm',
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.POST
        )

    @result_or_error
    def remove_user_roles(self, roles: List[str], user_id: str) -> dict:
        """ Removes roles from a specific user

        Args:
            roles List[str]: Roles to remove (name)
            user_id str: ID of the user the roles should be removed from

        Returns:
            dict: Proxied response payload
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f'{self.users_uri}/{user_id}/role-mappings/realm',
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.DELETE
        )

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_roles(self, role_names: List[str]) -> List[KeycloakRole]:
        """ Returns full entries of Roles based on role names

        Args:
            role_names List[str]: Roles that should be looked up (names)

        Returns:
             List[KeycloakRole]: Full entries stored at Keycloak.
        Notes:
            - The Keycloak RestAPI will only identify RoleRepresentations that use name AND id which is the only reason for existence of this function
        """
        roles = self.get_all_roles()
        return list(filter(lambda role: role.name in role_names, roles))

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_user_roles(self, user_id: str) -> List[KeycloakRole]:
        """ Gets all roles of an user

        Args:
            user_id (str): ID of the user of interest

        Returns:

        """
        return self._admin_request(url=f'{self.users_uri}/{user_id}/role-mappings/realm', method=HTTPMethod.GET)

    @result_or_error(response_model=KeycloakRole)
    def create_role(self, role_name: str) -> KeycloakRole:
        """ Create a role on the realm

        Args:
            role_name (str): Name of the new role

        Returns:
            KeycloakRole: If creation succeeded, else it will return the error
        """
        response = self._admin_request(url=self.roles_uri, data={'name': role_name}, method=HTTPMethod.POST)
        if response.status_code == 201:
            return self.get_roles(role_names=[role_name])[0]
        else:
            return response

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_all_roles(self) -> List[KeycloakRole]:
        """ Get all roles of the Keycloak realm

        Returns:
            List[KeycloakRole]: All roles of the realm
        """
        return self._admin_request(url=self.roles_uri, method=HTTPMethod.GET)

    @result_or_error
    def delete_role(self, role_name: str) -> dict:
        """ Deletes a role on the realm

        Args:
            role_name (str): The role (name) to delte

        Returns:
            dict: Proxied response payload
        """
        return self._admin_request(url=f'{self.roles_uri}/{role_name}', method=HTTPMethod.DELETE)

    @result_or_error(response_model=KeycloakUser)
    def create_user(
            self,
            first_name: str,
            last_name: str,
            username: str,
            email: str,
            password: str,
            enabled: bool = True,
            initial_roles: List[str] = None
    ) -> KeycloakUser:
        """

        Args:
            first_name (str): The first name of the new user
            last_name (str): The last name of the new user
            username (str): The username of the new user
            email (str): The email of the new user
            password (str): The password of the new user
            enabled (bool): True if the user should be able to be used
            initial_roles List[str]: The roles the user should posses

        Returns:
            KeycloakUser: If the creation succeeded

        Notes:
            - Also triggers the email verification email
        """
        data = {
            "email": email,
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "clientRoles": self.get_roles(initial_roles),
            "credentials": [
                {
                    "temporary": False,
                    "type": "password",
                    "value": password
                }
            ],
            "requiredActions": ["VERIFY_EMAIL"]
        }
        response = self._admin_request(url=self.users_uri, data=data, method=HTTPMethod.POST)
        if response.status_code == 201:
            user = self.get_user(query=f'username={username}')
            self.send_email_verification(user.id)
            return user
        else:
            return response

    @result_or_error
    def change_password(self, user_id: str, new_password: str) -> dict:
        """ Exchanges a users password.

        Args:
            user_id (str): The user ID of interest
            new_password (str): The new password

        Returns:
            dict: Proxied response payload

        Notes:
            - Possibly should be extended by an old password check
        """
        credentials = {"temporary": False, "type": "password", "value": new_password}
        return self._admin_request(url=f'{self.users_uri}/{user_id}/reset-password', data=credentials, method=HTTPMethod.PUT)

    @result_or_error
    def send_email_verification(self, user_id: str) -> dict:
        """ Sends the email to verify the email address

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload
        """
        return self._admin_request(url=f'{self.users_uri}/{user_id}/send-verify-email', method=HTTPMethod.PUT)

    @result_or_error(response_model=KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> KeycloakUser:
        """ Queries the keycloak API for a specific user either based on its ID or any **native** attribute

        Args:
            user_id (str): The user ID of interest
            query: Query string. e.g. `email=testuser@codespecialist.com` or `username=codespecialist`

        Returns:
            KeycloakUser: If the user was found
        """
        if user_id is None:
            response = self._admin_request(url=f'{self.users_uri}?{query}', method=HTTPMethod.GET)
            return KeycloakUser(**response.json()[0])
        else:
            response = self._admin_request(url=f'{self.users_uri}/{user_id}', method=HTTPMethod.GET)
            return KeycloakUser(**response.json())

    @result_or_error
    def delete_user(self, user_id: str) -> dict:
        """ Deletes an user

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload
        """
        return self._admin_request(url=f'{self.users_uri}/{user_id}', method=HTTPMethod.DELETE)

    @result_or_error(response_model=KeycloakUser, is_list=True)
    def get_all_users(self) -> List[KeycloakUser]:
        """ Returns all users of the realm

        Returns:
            List[KeycloakUser]: All Keycloak users of the realm
        """
        response = self._admin_request(url=self.users_uri, method=HTTPMethod.GET)
        return response

    @result_or_error(response_model=KeycloakIdentityProvider, is_list=True)
    def get_identity_providers(self) -> List[KeycloakIdentityProvider]:
        """ Returns all configured identity Providers

        Returns:
            List[KeycloakIdentityProvider]: All configured identity providers
        """
        return self._admin_request(url=self.providers_uri, method=HTTPMethod.GET).json()

    @property
    def admin_token(self) -> KeycloakToken:
        """ Requests an AccessToken on the `admin-cli` client

        Returns:
            KeycloakToken: A token, valid to perform admin actions
        """
        if self.token_is_valid(token=self._admin_token.access_token):
            return self._admin_token.access_token
        else:
            self._get_admin_token()
            return self.admin_token

    @result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        """ Models the password OAuth2 flow. Exchanges username and password for an access token.

        Args:
            username (str): Username used for login
            password (str): Password of the user

        Returns:
            KeycloakToken: If the exchange succeeds
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password"
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        return response

    @result_or_error(response_model=KeycloakToken)
    def exchange_authorization_code(self, session_state: str, code: str) -> KeycloakToken:
        """ Models the authorization code OAuth2 flow. Opening the URL provided by `login_uri` will result in a callback to the configured callback URL.
        The callback will also create a session_state and code query parameter that can be exchanged for an access token.

        Args:
            session_state (str): Salt to reduce the risk of successful attacks
            code (str): The authorization code

        Returns:
            KeycloakToken: If the exchange succeeds
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "session_state": session_state,
            "grant_type": "authorization_code",
            "redirect_uri": self.callback_uri
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        return response

    def _admin_request(self, url: str, method: HTTPMethod, data: dict = None, content_type: str = "application/json") -> Response:
        """ Private method that is the basis for any requests requiring admin access to the api. Will append the necessary `Authorization` header

        Args:
            url (str): The URL to be called
            method (HTTPMethod): The HTTP verb to be used
            data (dict): The payload of the request
            content_type (str): The content type of the request

        Returns:
            Response: Response of Keycloak
        """
        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.admin_token}"
        }
        return requests.request(method=method.name, url=url, data=json.dumps(data), headers=headers)

    @functools.cached_property
    def login_uri(self):
        return f'{self.authorization_uri}?response_type=code&client_id={self.client_id}&redirect_uri={self.callback_uri}'

    @functools.cached_property
    def authorization_uri(self):
        return self.open_id_configuration.get('authorization_endpoint')

    @functools.cached_property
    def token_uri(self):
        return self.open_id_configuration.get('token_endpoint')

    @functools.cached_property
    def logout_uri(self):
        return self.open_id_configuration.get('end_session_endpoint')

    @functools.cached_property
    def realm_uri(self):
        return f"{self.server_url}/realms/{self.realm}"

    @functools.cached_property
    def users_uri(self):
        return self.admin_uri(resource="users")

    @functools.cached_property
    def roles_uri(self):
        return self.admin_uri(resource="roles")

    @functools.cached_property
    def _admin_uri(self):
        return f"{self.server_url}/admin/realms/{self.realm}"

    @functools.cached_property
    def _open_id(self):
        return f"{self.realm_uri}/protocol/openid-connect"

    @functools.cached_property
    def providers_uri(self):
        return self.admin_uri(resource="identity-provider/instances")

    def admin_uri(self, resource: str):
        return f"{self._admin_uri}/{resource}"

    def open_id(self, resource: str):
        return f"{self._open_id}/{resource}"

    def token_is_valid(self, token: str, audience: str = None) -> bool:
        """ Validates an access token, optionally also its audience

        Args:
            token (str): The token to be verified
            audience (str): Optional audience. Will be checked if provided

        Returns:
            bool: True if the token is valid
        """
        try:
            options = {"verify_signature": True, "verify_aud": audience is not None, "verify_exp": True}
            jwt.decode(token, self.public_key, options=options, audience=audience)
            return True
        except (ExpiredSignatureError, JWTError):
            return False

    def __str__(self):
        return f'FastAPI Keycloak Integration'

    def __repr__(self):
        return f'{self.__str__()} <class {self.__class__} >'
