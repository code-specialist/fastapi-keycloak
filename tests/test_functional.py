from fastapi_keycloak import FastAPIKeycloak


class TestAPI:

    def test_startup(self):
        idp = FastAPIKeycloak(
            server_url="http://localhost:8085/auth",
            client_id="test-client",
            client_secret="GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE",
            admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
            realm="Test",
            callback_uri="http://localhost:8081/callback"
        )
        assert idp
        assert idp.admin_token
        return idp