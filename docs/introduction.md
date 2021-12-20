# Introduction

Welcome to `fastapi-keycloak`. This projects goal is to ease the integration of Keycloak (OpenID Connect) with Python, especially FastAPI. FastAPI is not necessary but is
encouraged due to specific features. Currently, this package supports only the `password flow`. However, the `get_current_user()` method accepts any JWT that was signed using
Keycloak's private key.

## TLDR;

FastAPI Keycloak enables you to do the following things without writing a single line of additional code:

- Verify identities and roles of users with Keycloak
- Get a list of available identity providers
- Create/read/delete users
- Create/read/delete roles
- Assign/Remove roles from users
- Implement the password flow (login/callback/logout)

## Example

### app.py

```python
import uvicorn
from fastapi import FastAPI, Depends

from fastapi_keycloak import FastAPIKeycloak, OIDCUser

app = FastAPI()
idp = FastAPIKeycloak(
    app=app,
    server_url="https://auth.some-domain.com/auth",
    client_id="some-client",
    client_secret="some-client-secret",
    admin_client_secret="admin-cli-secret",
    realm="some-realm-name",
    callback_uri="http://localhost:8081/callback"
)


@app.get("/premium", tags=["secured-endpoint"])
def premium(user: OIDCUser = Depends(idp.get_current_user(required_roles=["premium"]))):
    return f'Hi premium user {user}'


@app.get("/user/roles", tags=["secured-endpoint"])
def user_roles(user: OIDCUser = Depends(idp.get_current_user)):
    return f'{user.roles}'


if __name__ == '__main__':
    uvicorn.run('app:app', host="127.0.0.1", port=8081)
```

The `get_current_user()` method validates an `Access Token` that is given as `Authorization` HTTP-header e.g:

```shell
curl -H "Authorization: Bearer [ACCESS TOKEN]" -X GET http://localhost:8081/user/roles 
```

You may also retrieve an `Access Token` with login credentials:

```shell
curl -H "Authorization: Bearer [ACCESS TOKEN]" -X POST http://localhost:8081/user/roles 
```

## Install

```shell
pip install fastapi-keycloak
```