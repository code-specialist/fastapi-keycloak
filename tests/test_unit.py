# from fastapi_keycloak.model import KeycloakUser
# from tests import BaseTestClass
#
#
# class TestAPIUnit(BaseTestClass):
#
#     def test_create_users_and_roles(self, idp):
#         assert idp.get_all_users() == []
#         user_a = idp.create_user(
#             first_name="test",
#             last_name="user",
#             username="testuser_a@code-specialist.com",
#             email="testuser_a@code-specialist.com",
#             password="test-password",
#             enabled=True,
#             send_email_verification=False
#         )
#         assert user_a
#         assert isinstance(user_a, KeycloakUser)
#         assert len(idp.get_all_users()) == 1
#         user_b = idp.create_user(
#             first_name="test",
#             last_name="user",
#             username="testuser_b@code-specialist.com",
#             email="testuser_b@code-specialist.com",
#             password="test-password",
#             enabled=True,
#             send_email_verification=False
#         )
#         assert user_b
#         assert isinstance(user_b, KeycloakUser)
#         assert len(idp.get_all_users()) == 2
#         assert idp.get_user_roles(user_id=user_a.id)
#
#         assert idp.delete_user(user_id=user_a.id)
#         assert idp.delete_user(user_id=user_b.id)
