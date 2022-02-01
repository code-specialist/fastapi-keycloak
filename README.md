# FastAPI Keycloak Integration

[![CodeFactor](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak/badge)](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak)
[![codecov](https://codecov.io/gh/code-specialist/fastapi-keycloak/branch/master/graph/badge.svg?token=PX6NJBDUJ9)](https://codecov.io/gh/code-specialist/fastapi-keycloak)
---


Welcome to `fastapi-keycloak`. This projects goal is to ease the integration of Keycloak (OpenID Connect) with Python, especially FastAPI. FastAPI is not necessary but is
encouraged due to specific features. Currently, this package supports only the `password` and the `authorization_code`. However, the `get_current_user()` method accepts any JWT
that was signed using Keycloak´s private key.

## Docs

Docs are available at [https://fastapi-keycloak.code-specialist.com/](https://fastapi-keycloak.code-specialist.com/).

## TLDR

FastAPI Keycloak enables you to do the following things without writing a single line of additional code:

- Verify identities and roles of users with Keycloak
- Get a list of available identity providers
- Create/read/delete users
- Create/read/delete roles
- Create/read/delete/assign groups (recursive). Thanks to @fabiothz
- Assign/remove roles from users
- Implement the `password` or the `authorization_code` flow (login/callback/logout)

