# Quickstart

In order to just get started, we prepared some containers and configs for you.

## 1. Configure the Containers

**docker-compose.yaml**

```yaml hl_lines="16 18"
version: '3'

services:
  postgres:
    image: postgres
    environment:
      POSTGRES_DB: testkeycloakdb
      POSTGRES_USER: testkeycloakuser
      POSTGRES_PASSWORD: testkeycloakpassword
    restart:
      always

  keycloak:
    image: jboss/keycloak:16.1.0   
    volumes:
      - ./realm-export.json:/opt/jboss/keycloak/imports/realm-export.json
    command:
      - "-b 0.0.0.0 -Dkeycloak.profile.feature.upload_scripts=enabled -Dkeycloak.import=/opt/jboss/keycloak/imports/realm-export.json"
    environment:
      DB_VENDOR: POSTGRES
      DB_ADDR: postgres
      DB_DATABASE: testkeycloakdb
      DB_USER: testkeycloakuser
      DB_SCHEMA: public
      DB_PASSWORD: testkeycloakpassword
      KEYCLOAK_USER: keycloakuser
      KEYCLOAK_PASSWORD: keycloakpassword
      PROXY_ADDRESS_FORWARDING: "true"
      KEYCLOAK_LOGLEVEL: DEBUG
    ports:
      - '8085:8080'
    depends_on:
      - postgres
    restart:
      always
```

This will create a Postgres and a Keycloak container ready to use. Make sure to download the [realm-export.json](./downloads/realm-export.json) and keep it in the same folder as
the docker compose file to bind the configuration.

!!! Caution 
    These containers are stateless and non-persistent. Data will be lost on restart.

## 2. Start the Containers

Start the containers by applying the `docker-compose.yaml`:

```shell
docker-compose up -d
```

!!! info 
    When you want to delete the containers you may use `docker-compose down` in the same directory to kill the containers created with the `docker-compose.yaml`

## 3. The FastAPI App

You may use the code below without altering it, the imported config will match these values:

```python
import uvicorn
from fastapi import FastAPI, Depends
from fastapi.responses import RedirectResponse
from fastapi_keycloak import FastAPIKeycloak, OIDCUser

app = FastAPI()
idp = FastAPIKeycloak(
    server_url="http://localhost:8085/auth",
    client_id="test-client",
    client_secret="GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE",
    admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
    realm="Test",
    callback_uri="http://localhost:8081/callback"
)
idp.add_swagger_config(app)


@app.get("/")  # Unprotected
def root():
    return 'Hello World'


@app.get("/user")  # Requires logged in
def current_users(user: OIDCUser = Depends(idp.get_current_user())):
    return user


@app.get("/admin")  # Requires the admin role
def company_admin(user: OIDCUser = Depends(idp.get_current_user(required_roles=["admin"]))):
    return f'Hi admin {user}'


@app.get("/login")
def login_redirect():
    return RedirectResponse(idp.login_uri)


@app.get("/callback")
def callback(session_state: str, code: str):
    return idp.exchange_authorization_code(session_state=session_state, code=code)  # This will return an access token


if __name__ == '__main__':
    uvicorn.run('app:app', host="127.0.0.1", port=8081)
```

## 4. Usage

You may now use any of the [APIs exposed endpoints](reference.md) as everything is configured for testing all the features.

After you call the `/login` endpoint of your app, you will be redirected to the login screen of Keycloak. You may open the Keycloak Frontend at [http://localhost:8085/auth](http://localhost:8085/auth) and create a user. To
log into your Keycloak instance, the username is `keycloakuser` and the password is `keycloakpassword` as described in the `docker-compose.yaml` above. 

To utilize this fully you need a way to store the Access-Token provided by the callback route and append it to the preceding requests as `Authorization` Bearer.