from typing import List, Optional

import uvicorn
from fastapi import FastAPI, Depends, Query, Body
from pydantic import SecretStr

from fastapi_keycloak import FastAPIKeycloak, OIDCUser, UsernamePassword, HTTPMethod, KeycloakUser

app = FastAPI()
idp = FastAPIKeycloak(
    server_url="http://localhost:8085/auth",
    client_id="test-client",
    client_secret="GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE",
    admin_client_id="admin-cli",
    admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
    realm="Test",
    callback_uri="http://localhost:8081/callback"
)
idp.add_swagger_config(app)


# Admin

@app.post("/proxy", tags=["admin-cli"])
def proxy_admin_request(
        relative_path: str, method: HTTPMethod, additional_headers: dict = Body(None),
        payload: dict = Body(None)
):
    return idp.proxy(
        additional_headers=additional_headers,
        relative_path=relative_path,
        method=method,
        payload=payload
    )


@app.get("/identity-providers", tags=["admin-cli"])
def get_identity_providers():
    return idp.get_identity_providers()


@app.get("/idp-configuration", tags=["admin-cli"])
def get_idp_config():
    return idp.open_id_configuration


# User Management

@app.get("/users", tags=["user-management"])
def get_users():
    return idp.get_all_users()


@app.get("/user", tags=["user-management"])
def get_user_by_query(query: str = None):
    return idp.get_user(query=query)


@app.post("/users", tags=["user-management"])
def create_user(first_name: str, last_name: str, email: str, password: SecretStr, id: str = None):
    return idp.create_user(first_name=first_name, last_name=last_name, username=email, email=email,
                           password=password.get_secret_value(), id=id)


@app.get("/user/{user_id}", tags=["user-management"])
def get_user(user_id: str = None):
    return idp.get_user(user_id=user_id)


@app.put("/user", tags=["user-management"])
def update_user(user: KeycloakUser):
    return idp.update_user(user=user)


@app.delete("/user/{user_id}", tags=["user-management"])
def delete_user(user_id: str):
    return idp.delete_user(user_id=user_id)


@app.put("/user/{user_id}/change-password", tags=["user-management"])
def change_password(user_id: str, new_password: SecretStr):
    return idp.change_password(user_id=user_id, new_password=new_password)


@app.put("/user/{user_id}/send-email-verification", tags=["user-management"])
def send_email_verification(user_id: str):
    return idp.send_email_verification(user_id=user_id)


# Role Management

@app.get("/roles", tags=["role-management"])
def get_all_roles():
    return idp.get_all_roles()


@app.get("/role/{role_name}", tags=["role-management"])
def get_role(role_name: str):
    return idp.get_roles([role_name])


@app.post("/roles", tags=["role-management"])
def add_role(role_name: str):
    return idp.create_role(role_name=role_name)


@app.delete("/roles", tags=["role-management"])
def delete_roles(role_name: str):
    return idp.delete_role(role_name=role_name)


# Group Management

@app.get("/groups", tags=["group-management"])
def get_all_groups():
    return idp.get_all_groups()


@app.get("/group/{group_name}", tags=["group-management"])
def get_group(group_name: str):
    return idp.get_groups([group_name])


@app.get("/group-by-path/{path: path}", tags=["group-management"])
def get_group_by_path(path: str):
    return idp.get_group_by_path(path)


@app.post("/groups", tags=["group-management"])
def add_group(group_name: str, parent_id: Optional[str] = None):
    return idp.create_group(group_name=group_name, parent=parent_id)


@app.delete("/groups", tags=["group-management"])
def delete_groups(group_id: str):
    return idp.delete_group(group_id=group_id)


# User Roles

@app.post("/users/{user_id}/roles", tags=["user-roles"])
def add_roles_to_user(user_id: str, roles: Optional[List[str]] = Query(None)):
    return idp.add_user_roles(user_id=user_id, roles=roles)


@app.get("/users/{user_id}/roles", tags=["user-roles"])
def get_user_roles(user_id: str):
    return idp.get_user_roles(user_id=user_id)


@app.delete("/users/{user_id}/roles", tags=["user-roles"])
def delete_roles_from_user(user_id: str, roles: Optional[List[str]] = Query(None)):
    return idp.remove_user_roles(user_id=user_id, roles=roles)


# User Groups

@app.post("/users/{user_id}/groups", tags=["user-groups"])
def add_group_to_user(user_id: str, group_id: str):
    return idp.add_user_group(user_id=user_id, group_id=group_id)


@app.get("/users/{user_id}/groups", tags=["user-groups"])
def get_user_groups(user_id: str):
    return idp.get_user_groups(user_id=user_id)


@app.delete("/users/{user_id}/groups", tags=["user-groups"])
def delete_groups_from_user(user_id: str, group_id: str):
    return idp.remove_user_group(user_id=user_id, group_id=group_id)


# Example User Requests

@app.get("/protected", tags=["example-user-request"])
def protected(user: OIDCUser = Depends(idp.get_current_user())):
    return user


@app.get("/current_user/roles", tags=["example-user-request"])
def get_current_users_roles(user: OIDCUser = Depends(idp.get_current_user())):
    return user.roles


@app.get("/admin", tags=["example-user-request"])
def company_admin(user: OIDCUser = Depends(idp.get_current_user(required_roles=["admin"]))):
    return f'Hi admin {user}'


@app.get("/login", tags=["example-user-request"])
def login(user: UsernamePassword = Depends()):
    return idp.user_login(username=user.username, password=user.password.get_secret_value())


# Auth Flow

@app.get("/login-link", tags=["auth-flow"])
def login_redirect():
    return idp.login_uri


@app.get("/callback", tags=["auth-flow"])
def callback(session_state: str, code: str):
    return idp.exchange_authorization_code(session_state=session_state, code=code)


@app.get("/logout", tags=["auth-flow"])
def logout():
    return idp.logout_uri


if __name__ == '__main__':
    uvicorn.run('app:app', host="127.0.0.1", port=8081)
