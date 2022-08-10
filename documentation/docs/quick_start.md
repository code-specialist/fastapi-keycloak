# Quickstart

In order to just get started, we prepared some containers and configs for you.

## 1. Configure the Containers

**docker-compose.yaml**

```yaml hl_lines="16 18"
{!examples/quickstart/docker-compose.yaml!}
```

This will create a Postgres and a Keycloak container ready to use. Make sure to download the [realm-export.json](./examples/quickstart/realm-export.json) and keep it in the same folder as
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
{!examples/quickstart/app.py!}
```

## 4. Usage

You may now use any of the [APIs exposed endpoints](reference.md) as everything is configured for testing all the features.

After you call the `/login` endpoint of your app, you will be redirected to the login screen of Keycloak. You may open the Keycloak Frontend at [http://localhost:8085/auth](http://localhost:8085/auth) and create a user. To
log into your Keycloak instance, the username is `keycloakuser` and the password is `keycloakpassword` as described in the `docker-compose.yaml` above. 

To utilize this fully you need a way to store the Access-Token provided by the callback route and append it to the preceding requests as `Authorization` Bearer.
