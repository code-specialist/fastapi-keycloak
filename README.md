# FastAPI Keycloak Integration

[![Test-Suite](https://github.com/code-specialist/fastapi-keycloak/actions/workflows/testing.yaml/badge.svg)](https://github.com/code-specialist/fastapi-keycloak/actions/workflows/testing.yaml)
[![CodeFactor](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak/badge)](https://www.codefactor.io/repository/github/code-specialist/fastapi-keycloak)
[![codecov](https://codecov.io/gh/code-specialist/fastapi-keycloak/branch/master/graph/badge.svg?token=PX6NJBDUJ9)](https://codecov.io/gh/code-specialist/fastapi-keycloak)
![Py3.8](https://img.shields.io/badge/-Python%203.8-brightgreen)
![Py3.9](https://img.shields.io/badge/-Python%203.9-brightgreen)
![Py3.10](https://img.shields.io/badge/-Python%203.10-brightgreen)
[![CodeQL](https://github.com/code-specialist/fastapi-keycloak/actions/workflows/codeql.yml/badge.svg)](https://github.com/code-specialist/fastapi-keycloak/actions/workflows/codeql.yml)

---

## Notice - 📢 LOOKING FOR MAINTAINERS 📢

We created this as an open-source project in order to share our code with other people. Unfortunately we decided to abandon Keycloak in our project due to its unreliability in API compatibility and the general maintenance overhead. Therefore, we are no longer able to frequently update this library. We are searching for someone or a group of people to maintain this repository actively, as we do not have the capacity but think that keycloak still is a highly relevant IDP solution. If you or your team want to take over the responsibility, please mail us at [admin@code-specialist.com](mailto:admin@code-specialist.com)

## Introduction

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

## Contributions

We would like encourage anyone using this package to contribute to its improvement, if anything isn't working as expected or isn't well enough documented, please open an issue or a
pull request. Please note that for any code contribution tests are required.

### Testing

Tests are stored and executed in `./tests`. To test the package, it is necessary to use the `start_infra.sh` script upfront, to set up Keycloak and Postgres. We do this to avoid
artificial testing conditions that occur by mocking all the keycloak requests. The issue here is that we currently see no way to offer public testing opportunities without
significant security issues, which is why you have to run these tests locally and provide a `test_coverage.xml` file. The test coverage is configured in the `pytest.ini` and will
be created once the tests finished running (locally).
