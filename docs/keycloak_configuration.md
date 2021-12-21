# Keycloak sample configuration

1. Create a new realm 
   1. **General**: Enabled, OpenID Endpoint Configuration
   3. **Login**: User registration enabled
2. Create a new client
   1. **Settings**: Enabled, Direct Access Granted, Service Accounts Enabled, Authorization Enabled
   2. Valid Redirect URIs: `http://localhost:8081/callback` (Or whatever you configure in your python app)
3. Modify the `admin-cli` client
   1. **Settings**: Service Accounts Enabled
   2. **Scope**: Full Scope Allowed
   3. **Service Account Roles**: Select all Client Roles available for `account` and `realm_management`