from __future__ import annotations

import functools
import json
from typing import List

import requests
from fastapi import Depends, HTTPException, FastAPI
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, ExpiredSignatureError, JWTError
from requests import Response

from functions import forward_response, ForwardedResponse, result_or_error
from model import HTTPMethod, KeycloakUser, OIDCUser, KeycloakToken, KeycloakRole, KeycloakIdentityProvider


class FastAPIKeycloak:
    """ Instance to wrap the Keycloak API with FastAPI """
    _admin_token: KeycloakToken

    def __init__(self, server_url: str, client_id: str, client_secret: str, realm: str, admin_client_secret: str, callback_uri: str, app: FastAPI = None):
        """

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
        if app:
            app.swagger_ui_init_oauth = {
                "usePkceWithAuthorizationCodeGrant": True,
                "clientId": self.client_id,
                "clientSecret": self.client_secret
            }

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        return OAuth2PasswordBearer(tokenUrl=self.token_uri)

    def get_current_user(self, required_roles: List[str] = None) -> OIDCUser:

        def current_user(token: OAuth2PasswordBearer = Depends(self.user_auth_scheme)) -> OIDCUser:
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
        response = requests.get(url=f'{self.realm_uri}/.well-known/openid-configuration')
        return response.json()

    @forward_response
    def proxy(self, additional_headers: dict, relative_path: str, method: HTTPMethod, payload: dict):
        return requests.request(
            method=method.name,
            url=f'{self.server_url}{relative_path}',
            data=json.dumps(payload),
            headers={"Authorization": f"Bearer {self.admin_token}", **additional_headers}
        )

    def _get_admin_token(self):
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
        response = requests.get(url=self.realm_uri)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    @forward_response
    def add_user_roles(self, roles: List[str], user_id: str):
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f'{self.users_uri}/{user_id}/role-mappings/realm',
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.POST
        )

    @forward_response
    def remove_user_roles(self, roles: List[str], user_id: str):
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f'{self.users_uri}/{user_id}/role-mappings/realm',
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.DELETE
        )

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_roles(self, role_names: List[str]) -> List[KeycloakRole]:
        roles = self.get_all_roles()
        return list(filter(lambda role: role.name in role_names, roles))

    @forward_response
    def get_user_roles(self, user_id: str) -> ForwardedResponse:
        return self._admin_request(url=f'{self.users_uri}/{user_id}/role-mappings/realm', method=HTTPMethod.GET)

    @result_or_error(response_model=KeycloakRole)
    def create_role(self, role_name: str) -> ForwardedResponse:
        response = self._admin_request(url=self.roles_uri, data={'name': role_name}, method=HTTPMethod.POST)
        if response.status_code == 201:
            return self.get_roles(role_names=[role_name])[0]
        else:
            return response

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_all_roles(self) -> ForwardedResponse:
        return self._admin_request(url=self.roles_uri, method=HTTPMethod.GET)

    @result_or_error
    def delete_role(self, role_name: str) -> ForwardedResponse:
        return self._admin_request(url=f'{self.roles_uri}/{role_name}', method=HTTPMethod.DELETE)

    @result_or_error(response_model=KeycloakUser)
    def create_user(
            self,
            first_name: str,
            last_name: str,
            username: str,
            email: str,
            password: str,
            id: str = None,
            enabled: bool = True,
            initial_roles: List[str] = None
    ) -> KeycloakUser:
        data = {
            "id": id,
            "email": email,
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "clientRoles": initial_roles,
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

    @forward_response
    def change_password(self, user_id: str, new_password: str) -> ForwardedResponse:
        credentials = {"temporary": False, "type": "password", "value": new_password}
        return self._admin_request(url=f'{self.users_uri}/{user_id}/reset-password', data=credentials, method=HTTPMethod.PUT)

    @forward_response
    def send_email_verification(self, user_id: str) -> ForwardedResponse:
        return self._admin_request(url=f'{self.users_uri}/{user_id}/send-verify-email', method=HTTPMethod.PUT)

    @result_or_error(response_model=KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> KeycloakUser:
        if user_id is None:
            response = self._admin_request(url=f'{self.users_uri}?{query}', method=HTTPMethod.GET)
            return KeycloakUser(**response.json()[0])
        else:
            response = self._admin_request(url=f'{self.users_uri}/{user_id}', method=HTTPMethod.GET)
            return KeycloakUser(**response.json())

    @result_or_error(response_model=KeycloakUser)
    def delete_user(self, user_id: str) -> KeycloakUser:
        return self._admin_request(url=f'{self.users_uri}/{user_id}', method=HTTPMethod.DELETE)

    @result_or_error(response_model=KeycloakUser, is_list=True)
    def get_users(self) -> List[KeycloakUser]:
        response = self._admin_request(url=self.users_uri, method=HTTPMethod.GET)
        return response

    @result_or_error(response_model=KeycloakIdentityProvider, is_list=True)
    def get_identity_providers(self) -> List[KeycloakIdentityProvider]:
        return self._admin_request(url=self.providers_uri, method=HTTPMethod.GET).json()

    @property
    def admin_token(self) -> KeycloakToken:
        if self.token_is_valid(token=self._admin_token.access_token):
            return self._admin_token.access_token
        else:
            self._get_admin_token()
            return self.admin_token

    @result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"client_id": self.client_id, "client_secret": self.client_secret, "username": username, "password": password, "grant_type": "password"}
        response = requests.post(url=self.token_uri, headers=headers, data=data)
        return response

    @result_or_error(response_model=KeycloakToken)
    def exchange_authorization_code(self, session_state: str, code: str) -> KeycloakToken:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
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
