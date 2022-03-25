from typing import List

import pytest as pytest
from fastapi import HTTPException

from fastapi_keycloak import KeycloakError
from fastapi_keycloak.exceptions import (
    VerifyEmailException,
    UpdateUserLocaleException,
    ConfigureTOTPException,
    UpdatePasswordException,
    UpdateProfileException,
)
from fastapi_keycloak.model import (
    KeycloakGroup,
    KeycloakUser,
    KeycloakRole,
    KeycloakToken,
    OIDCUser,
)
from tests import BaseTestClass

TEST_PASSWORD = "test-password"


class TestAPIFunctional(BaseTestClass):

    @pytest.fixture
    def user(self, idp):
        return idp.create_user(
            first_name="test",
            last_name="user",
            username="user@code-specialist.com",
            email="user@code-specialist.com",
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False
        )

    @pytest.fixture()
    def users(self, idp):
        assert idp.get_all_users() == []  # No users yet

        # Create some test users
        user_alice = idp.create_user(  # Create User A
            first_name="test",
            last_name="user",
            username="testuser_alice@code-specialist.com",
            email="testuser_alice@code-specialist.com",
            password=TEST_PASSWORD,
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
                password=TEST_PASSWORD,
                enabled=True,
                send_email_verification=False
            )
        assert len(idp.get_all_users()) == 1

        user_bob = idp.create_user(  # Create User B
            first_name="test",
            last_name="user",
            username="testuser_bob@code-specialist.com",
            email="testuser_bob@code-specialist.com",
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False
        )
        assert isinstance(user_bob, KeycloakUser)
        assert len(idp.get_all_users()) == 2
        return user_alice, user_bob

    def test_roles(self, idp, users):
        user_alice, user_bob = users

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
            assert role.name in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name,
                                 test_role_mars.name]

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
        keycloak_token_alice: KeycloakToken = idp.user_login(username=user_alice.username, password=TEST_PASSWORD)
        assert idp.token_is_valid(keycloak_token_alice.access_token)
        keycloak_token_bob: KeycloakToken = idp.user_login(username=user_bob.username, password=TEST_PASSWORD)
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
            assert role in ["default-roles-test", "offline_access", "uma_authorization", test_role_saturn.name,
                            test_role_mars.name]

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

    def test_groups(self, idp):

        # None of empty list groups
        none_return = idp.get_groups([])
        assert not none_return

        # None of none param
        none_return = idp.get_groups(None)
        assert none_return is None

        # Error create group
        with pytest.raises(KeycloakError):
            idp.create_group(group_name=None)

        # Error get group
        with pytest.raises(KeycloakError):
            idp.get_group(group_id=None)

        # Create the first group
        foo_group: KeycloakGroup = idp.create_group(group_name='Foo Group')
        assert foo_group is not None
        assert foo_group.name == 'Foo Group'

        # Get Empty Subgroups for group
        empty_subgroups = idp.get_subgroups(foo_group, '/nonexistent')
        assert empty_subgroups is None

        # Find Group by invalid Path
        invalid_group = idp.get_group_by_path('/nonexistent')
        assert invalid_group is None

        # Create the second group
        bar_group: KeycloakGroup = idp.create_group(group_name='Bar Group')
        assert bar_group is not None
        assert bar_group.name == 'Bar Group'

        # Check if groups are registered
        all_groups: List[KeycloakGroup] = idp.get_all_groups()
        assert len(all_groups) == 2

        # Check get_groups
        groups: List[KeycloakGroup] = idp.get_groups(group_names=[foo_group.name])
        assert len(groups) == 1
        assert groups[0].name == foo_group.name

        # Create Subgroup 1 by parent object
        subgroup1: KeycloakGroup = idp.create_group(group_name='Subgroup 01', parent=foo_group)
        assert subgroup1 is not None
        assert subgroup1.name == 'Subgroup 01'
        assert subgroup1.path == f'{foo_group.path}/Subgroup 01'

        # Create Subgroup 2 by parent id
        subgroup2: KeycloakGroup = idp.create_group(group_name='Subgroup 02', parent=foo_group.id)
        assert subgroup2 is not None
        assert subgroup2.name == 'Subgroup 02'
        assert subgroup2.path == f'{foo_group.path}/Subgroup 02'

        # Create Subgroup Level 3
        subgroup_l3: KeycloakGroup = idp.create_group(group_name='Subgroup l3', parent=subgroup2)
        assert subgroup_l3 is not None
        assert subgroup_l3.name == 'Subgroup l3'
        assert subgroup_l3.path == f'{subgroup2.path}/Subgroup l3'

        # Create Subgroup Level 4
        subgroup_l4: KeycloakGroup = idp.create_group(group_name='Subgroup l4', parent=subgroup_l3)
        assert subgroup_l4 is not None
        assert subgroup_l4.name == 'Subgroup l4'
        assert subgroup_l4.path == f'{subgroup_l3.path}/Subgroup l4'

        # Find Group by Path
        foo_group = idp.get_group_by_path(foo_group.path)
        assert foo_group is not None
        assert len(foo_group.subGroups) == 2

        # Find Subgroup by Path        
        subgroup_by_path = idp.get_group_by_path(subgroup2.path)
        assert subgroup_by_path is not None
        assert subgroup_by_path.id == subgroup2.id

        # Find subgroup that does not exist
        subgroup_by_path = idp.get_group_by_path('/The Subgroup/Not Exists')
        assert subgroup_by_path is None

        # Clean up
        idp.delete_group(group_id=bar_group.id)
        idp.delete_group(group_id=foo_group.id)

    def test_user_groups(self, idp, user):

        # Check initial user groups
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 0

        # Create the first group and add to user
        foo_group: KeycloakGroup = idp.create_group(group_name='Foo')
        idp.add_user_group(user_id=user.id, group_id=foo_group.id)

        # Check if the user is in the group
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 1
        assert user_groups[0].id == foo_group.id

        # Remove User of the group
        idp.remove_user_group(user.id, foo_group.id)

        # Check if the user has no group
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 0

        idp.delete_group(group_id=foo_group.id)
        idp.delete_user(user_id=user.id)

    @pytest.mark.parametrize("action, exception", [
        ("update_user_locale", UpdateUserLocaleException),
        ("CONFIGURE_TOTP", ConfigureTOTPException),
        ("VERIFY_EMAIL", VerifyEmailException),
        ("UPDATE_PASSWORD", UpdatePasswordException),
        ("UPDATE_PROFILE", UpdateProfileException),
    ])
    def test_login_exceptions(self, idp, action, exception, user):

        # Get access tokens for the users
        access_token = idp.user_login(username=user.username, password=TEST_PASSWORD)
        assert access_token

        user.requiredActions.append(action)  # Add an action
        user: KeycloakUser = idp.update_user(user=user)  # Save the change

        with pytest.raises(exception):  # Expect the login to fail due to the verify email action
            idp.user_login(username=user.username, password=TEST_PASSWORD)

        user.requiredActions.remove(action)  # Remove the action
        user: KeycloakUser = idp.update_user(user=user)  # Save the change
        assert idp.user_login(username=user.username, password=TEST_PASSWORD)  # Login possible again

        # Clean up
        idp.delete_user(user_id=user.id)
