# Quickstart

In order to just get started, we prepared some containers and configs for you.

!!! info
    If you have cloned the git repo, you can run this from the examples dir `fastapi-keycloak/documentation/docs/examples/quickstart`

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

To utilize this fully you need a way to store the Access-Token provided by the callback route and add it to any further requests as `Authorization` Bearer.

You can test this with curl like so:

```shell
# TOKEN should be changed to the value of 'access_token'.
# This can be aquired once you have visited http://localhost:8081/login

TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrbF9ITTQyMHVmcVVwYmhxcHJYVFBzelNlOWZocmdkamtZZF9EbmVhb0dVIn0.eyJleHAiOjE2NjAxNDUwOTAsImlhdCI6MTY2MDE0NDc5MCwiYXV0aF90aW1lIjoxNjYwMTQ0Nzc2LCJqdGkiOiI4YTI3MmEyYS1mMDMxLTQ0ZDctOWRkNy0zMTM4MDQ2ZWQyOTciLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODUvYXV0aC9yZWFsbXMvVGVzdCIsInN1YiI6ImUxZGEwZWYzLTVhMmQtNGMyYi05NGQ4LWQwN2E2Zjc3Y2JhMyIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjM5Mzc4ODVkLTk0Y2MtNDIyMy05YjczLWI2YmRiMGM1MzJlZiIsImFjciI6IjAiLCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJzaWQiOiIzOTM3ODg1ZC05NGNjLTQyMjMtOWI3My1iNmJkYjBjNTMyZWYiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJNaWNoYWVsIFJvYmluc29uIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibGF4ZG9nQGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJNaWNoYWVsIiwiZmFtaWx5X25hbWUiOiJSb2JpbnNvbiIsImVtYWlsIjoibGF4ZG9nQGdtYWlsLmNvbSJ9.FQEtefB90W53L_MHXmhm15223zemd-eb-yMDNtup-lZ9-tEyW5FhE0ro-WzEVypAllQ3b1hH0mx_vZ_wxL00wTzXG_Vi_eMT5U5HTJA6UcwR-Ogv6B1BL42l6xwXQCVLTVgrIKBf1NcJbv0k0qD0Zt-VN1S32JPKr0lURdL99idnIOzWVWrS_urG_2R2RiIn-xTcqyGyxbHkBlPbnk55p9NKl_o1lsnBH-8bJme5c35tA6YTyd8Y2tI7zPHYHZ9s8mBlxrsVLubwAZj12L3cZuG1g_H9uASBOxYbfXwX8CR6lQJ2lTaYcfRriCBOMkTzGwb8VoIG8ti9dv9gJTSgSw"

curl -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}"  http://localhost:8081/user
```
