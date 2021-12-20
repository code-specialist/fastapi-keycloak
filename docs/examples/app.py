
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


@app.get("/user/info", tags=["secured-endpoint"])
def premium(user: OIDCUser = Depends(idp.get_current_user)):
    return f'Hi user {user}'


if __name__ == '__main__':
    uvicorn.run('app:app', host="127.0.0.1", port=8081)