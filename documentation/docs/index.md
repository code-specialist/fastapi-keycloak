# FastAPI Keycloak Integration

[![CodeFactor](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak/badge)](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak)
[![codecov](https://codecov.io/gh/code-specialist/fastapi-keycloak/branch/master/graph/badge.svg?token=PX6NJBDUJ9)](https://codecov.io/gh/code-specialist/fastapi-keycloak)

---

## Introduction

Welcome to `fastapi-keycloak`. This projects goal is to ease the integration of Keycloak (OpenID Connect) with Python, especially FastAPI. FastAPI is not necessary but is
encouraged due to specific features. Currently, this package supports only the `password` and the `authorization_code` flow. However, the `get_current_user()` method accepts any 
JWT that was signed using Keycloak's private key.

## Installation

```shell
pip install fastapi_keycloak
```

## TLDR;

FastAPI Keycloak enables you to do the following things without writing a single line of additional code:

- Verify identities and roles of users with Keycloak
- Get a list of available identity providers
- Create/read/delete users
- Create/read/delete roles
- Assign/remove roles from users
- Implement the `password` or the `authorization_code` flow (login/callback/logout)

## Example

This example assumes you use a frontend technology (such as React, Vue, or whatever suits you) to render your pages and merely depicts a `protected backend`

### app.py

```python
{!examples/introduction/app.py!}
```
