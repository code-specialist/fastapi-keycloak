# Keycloak sample configuration

## Create a new realm
1. **General**: Enabled, OpenID Endpoint Configuration
2. **Login**: User registration enabled
## Create a new client
1. **Settings**: Enabled, Direct Access Granted, Service Accounts Enabled, Authorization Enabled
2. **Scope**: Full Scope Allowed (Will automatically grant all available roles to all users using this client, you may want to disable this and assign the roles to the 
   client manually)
3. Valid Redirect URIs: `http://localhost:8081/callback` (Or whatever you configure in your python app)
## Modify the `admin-cli` client
1. **Settings**: Service Accounts Enabled
2. **Scope**: Full Scope Allowed
3. **Service Account Roles**: Select all Client Roles available for `account` and `realm_management`