from typing import List

import pytest as pytest
from fastapi import HTTPException

from fastapi_keycloak import KeycloakError
from fastapi_keycloak.model import KeycloakUser, KeycloakRole, KeycloakToken, OIDCUser
from tests import BaseTestClass


class TestAPIFunctional(BaseTestClass):

    def test_functional_a(self, idp):
        assert idp.get_all_users() == []  # No users yet

        # Create some test users
        user_alice = idp.create_user(  # Create User A
            first_name="test",
            last_name="user",
            username="testuser_alice@code-specialist.com",
            email="testuser_alice@code-specialist.com",
            password="test-password",
            enabled=True,
            send_email_verification=False
        )
        assert isinstance(user_alice, KeycloakUser)
        assert len(idp.get_all_users()) == 1

        # Try to create a user with the same username
        with pytest.raises(KeycloakError):  # 'User exists with same username'
            idp.create_user(
                first_name="test",
                last_name="user",
                username="testuser_alice@code-specialist.com",
                email="testuser_alice@code-specialist.com",
                password="test-password",
                enabled=True,
                send_email_verification=False
            )
        assert len(idp.get_all_users()) == 1

        user_bob = idp.create_user(  # Create User B
            first_name="test",
            last_name="user",
            username="testuser_bob@code-specialist.com",
            email="testuser_bob@code-specialist.com",
            password="test-password",
            enabled=True,
            send_email_verification=False
        )
        assert isinstance(user_bob, KeycloakUser)
        assert len(idp.get_all_users()) == 2

        # Check the roles
        user_alice_roles = idp.get_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        user_bob_roles = idp.get_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Create a some roles
        all_roles = idp.get_all_roles()
        assert len(all_roles) == 3
        for role in all_roles:
            assert role.name in ["default-roles-test", "offline_access", "uma_authorization"]

        test_role_saturn = idp.create_role("test_role_saturn")
        all_roles = idp.get_all_roles()
        assert len(all_roles) == 4
        for role in all_roles:
            assert role.name in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name]

        test_role_mars = idp.create_role("test_role_mars")
        all_roles = idp.get_all_roles()
        assert len(all_roles) == 5
        for role in all_roles:
            assert role.name in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name, test_role_mars.name]

        assert isinstance(test_role_saturn, KeycloakRole)
        assert isinstance(test_role_mars, KeycloakRole)

        # Check the roles again
        user_alice_roles: List[KeycloakRole] = idp.get_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        user_bob_roles = idp.get_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Assign role to Alice
        idp.add_user_roles(user_id=user_alice.id, roles=[test_role_saturn.name])
        user_alice_roles: List[KeycloakRole] = idp.get_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 2
        for role in user_alice_roles:
            assert role.name in ["default-roles-test", test_role_saturn.name]

        # Assign roles to Bob
        idp.add_user_roles(user_id=user_bob.id, roles=[test_role_saturn.name, test_role_mars.name])
        user_bob_roles: List[KeycloakRole] = idp.get_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 3
        for role in user_bob_roles:
            assert role.name in ["default-roles-test", test_role_saturn.name, test_role_mars.name]

        # Exchange the details for access tokens
        keycloak_token_alice: KeycloakToken = idp.user_login(username=user_alice.username, password="test-password")
        assert idp.token_is_valid(keycloak_token_alice.access_token)
        keycloak_token_bob: KeycloakToken = idp.user_login(username=user_bob.username, password="test-password")
        assert idp.token_is_valid(keycloak_token_bob.access_token)

        # Check get_current_user Alice
        current_user_function = idp.get_current_user()
        current_user: OIDCUser = current_user_function(token=keycloak_token_alice.access_token)
        assert current_user.sub == user_alice.id
        assert len(current_user.roles) == 4  # Also includes all implicit roles
        for role in current_user.roles:
            assert role in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name]

        # Check get_current_user Bob
        current_user_function = idp.get_current_user()
        current_user: OIDCUser = current_user_function(token=keycloak_token_bob.access_token)
        assert current_user.sub == user_bob.id
        assert len(current_user.roles) == 5  # Also includes all implicit roles
        for role in current_user.roles:
            assert role in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name, test_role_mars.name]

        # Check get_current_user Alice with role Saturn
        current_user_function = idp.get_current_user(required_roles=[test_role_saturn.name])
        # Get Alice
        current_user: OIDCUser = current_user_function(token=keycloak_token_alice.access_token)
        assert current_user.sub == user_alice.id
        # Get Bob
        current_user: OIDCUser = current_user_function(token=keycloak_token_bob.access_token)
        assert current_user.sub == user_bob.id

        # Check get_current_user Alice with role Mars
        current_user_function = idp.get_current_user(required_roles=[test_role_mars.name])
        # Get Alice
        with pytest.raises(HTTPException):
            current_user_function(token=keycloak_token_alice.access_token)  # Alice does not posses this role
        # Get Bob
        current_user: OIDCUser = current_user_function(token=keycloak_token_bob.access_token)
        assert current_user.sub == user_bob.id

        # Remove Role Mars from Bob
        idp.remove_user_roles(user_id=user_bob.id, roles=[test_role_mars.name])
        user_bob_roles: List[KeycloakRole] = idp.get_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 2
        for role in user_bob_roles:
            assert role.name in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name]

        # Delete Role Saturn
        idp.delete_role(role_name=test_role_saturn.name)

        # Check Alice
        user_alice_roles: List[KeycloakRole] = idp.get_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        # Check Bob
        user_bob_roles = idp.get_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Clean up
        idp.delete_role(role_name=test_role_mars.name)
        idp.delete_user(user_id=user_alice.id)
        idp.delete_user(user_id=user_bob.id)
