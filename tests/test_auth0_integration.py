"""
Auth0 Integration Tests

WHY: Verify Auth0 authentication and authorization flows
HOW: Test JWT validation, token exchange, user management, and RBAC
IMPACT: Ensures enterprise-grade authentication security

Truth Protocol: Comprehensive coverage, no placeholders, security-focused testing
"""
from datetime import datetime, timedelta
import os
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from jose import jwt
import pytest


# Skip tests if auth0 module is not available
pytest.importorskip("security.auth0_integration")

from security.auth0_integration import (
    AUTH0_AUDIENCE,
    AUTH0_DOMAIN,
    Auth0Client,
    Auth0User,
    TokenPayload,
    auth0_health_check,
    auth0_oauth_client,
    create_devskyy_jwt_token,
    create_devskyy_refresh_token,
    get_auth0_login_url,
    get_current_admin_user,
    log_auth_event,
    require_permissions,
    require_scope,
    verify_devskyy_jwt_token,
    verify_jwt_token,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_auth0_user():
    """Create a mock Auth0 user."""
    return Auth0User(
        sub="auth0|123456789",
        email="test@example.com",
        email_verified=True,
        name="Test User",
        given_name="Test",
        family_name="User",
        picture="https://example.com/avatar.jpg",
        locale="en",
        role="user",
        permissions=["read:data", "write:data"],
        organization="test-org",
        subscription_tier="premium",
    )


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return Auth0User(
        sub="auth0|admin123",
        email="admin@example.com",
        email_verified=True,
        name="Admin User",
        role="admin",
        permissions=["read:data", "write:data", "admin:all"],
        organization="test-org",
        subscription_tier="enterprise",
    )


@pytest.fixture
def mock_token_payload():
    """Create a mock token payload."""
    return TokenPayload(
        sub="auth0|123456789",
        aud=[AUTH0_AUDIENCE],
        iss=f"https://{AUTH0_DOMAIN}/",
        exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        iat=int(datetime.utcnow().timestamp()),
        scope="openid profile email read:data",
        permissions=["read:data", "write:data"],
        role="user",
        organization="test-org",
    )


@pytest.fixture
def mock_jwks():
    """Create mock JWKS response."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "n": "test_n_value",
                "e": "AQAB",
                "kid": "test-key-id",
                "alg": "RS256",
            }
        ]
    }


@pytest.fixture
def valid_devskyy_token():
    """Create a valid DevSkyy JWT token for testing."""
    secret = os.getenv("SECRET_KEY", "test-secret-key-for-testing-only")
    payload = {
        "sub": "auth0|123456789",
        "email": "test@example.com",
        "name": "Test User",
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
        "iss": "devskyy-platform",
        "aud": "devskyy-api",
        "token_type": "access",
        "auth_provider": "auth0",
    }
    return jwt.encode(payload, secret, algorithm="HS256")


# ============================================================================
# MODEL TESTS
# ============================================================================


class TestAuth0User:
    """Test Auth0User model."""

    def test_create_user(self, mock_auth0_user):
        """Test creating an Auth0 user."""
        assert mock_auth0_user.sub == "auth0|123456789"
        assert mock_auth0_user.email == "test@example.com"
        assert mock_auth0_user.email_verified is True
        assert mock_auth0_user.role == "user"
        assert "read:data" in mock_auth0_user.permissions

    def test_user_default_values(self):
        """Test default values for Auth0User."""
        user = Auth0User(sub="auth0|minimal")
        assert user.email is None
        assert user.email_verified is False
        assert user.role == "user"
        assert user.permissions == []
        assert user.subscription_tier == "free"

    def test_user_with_custom_fields(self):
        """Test Auth0User with custom DevSkyy fields."""
        user = Auth0User(
            sub="auth0|custom",
            role="super_admin",
            organization="custom-org",
            subscription_tier="enterprise",
            permissions=["admin:all"],
        )
        assert user.role == "super_admin"
        assert user.organization == "custom-org"
        assert user.subscription_tier == "enterprise"


class TestTokenPayload:
    """Test TokenPayload model."""

    def test_create_token_payload(self, mock_token_payload):
        """Test creating a token payload."""
        assert mock_token_payload.sub == "auth0|123456789"
        assert AUTH0_AUDIENCE in mock_token_payload.aud
        assert mock_token_payload.scope is not None
        assert "read:data" in mock_token_payload.permissions

    def test_token_payload_default_values(self):
        """Test default values for TokenPayload."""
        payload = TokenPayload(
            sub="auth0|test",
            aud=["test-audience"],
            iss="https://test.auth0.com/",
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            iat=int(datetime.utcnow().timestamp()),
        )
        assert payload.scope == ""
        assert payload.permissions == []
        assert payload.role == "user"


# ============================================================================
# OAUTH2 CLIENT TESTS
# ============================================================================


class TestAuth0OAuth2Client:
    """Test Auth0 OAuth2 client."""

    def test_get_authorization_url(self):
        """Test generating authorization URL."""
        redirect_uri = "https://example.com/callback"
        state = "random-state-value"

        url = auth0_oauth_client.get_authorization_url(redirect_uri, state)

        assert AUTH0_DOMAIN in url
        assert "response_type=code" in url
        assert f"redirect_uri={redirect_uri}" in url or "redirect_uri=" in url
        assert f"state={state}" in url

    def test_get_authorization_url_without_state(self):
        """Test authorization URL without state."""
        redirect_uri = "https://example.com/callback"

        url = auth0_oauth_client.get_authorization_url(redirect_uri)

        assert "state=" not in url

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_success(self):
        """Test successful code exchange."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 86400,
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            result = await auth0_oauth_client.exchange_code_for_token(
                code="test-code",
                redirect_uri="https://example.com/callback",
            )

            assert result["access_token"] == "test-access-token"
            assert result["token_type"] == "Bearer"

    @pytest.mark.asyncio
    async def test_exchange_code_for_token_failure(self):
        """Test failed code exchange."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = "Invalid code"

            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            with pytest.raises(HTTPException) as exc_info:
                await auth0_oauth_client.exchange_code_for_token(
                    code="invalid-code",
                    redirect_uri="https://example.com/callback",
                )

            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_get_user_info_success(self):
        """Test getting user info from Auth0."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "sub": "auth0|123",
                "email": "user@example.com",
                "name": "Test User",
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            result = await auth0_oauth_client.get_user_info("test-token")

            assert result["sub"] == "auth0|123"
            assert result["email"] == "user@example.com"

    def test_get_logout_url(self):
        """Test generating logout URL."""
        return_to = "https://example.com"

        url = auth0_oauth_client.get_logout_url(return_to)

        assert AUTH0_DOMAIN in url
        assert "logout" in url
        assert "returnTo=" in url


# ============================================================================
# AUTH0 MANAGEMENT CLIENT TESTS
# ============================================================================


class TestAuth0Client:
    """Test Auth0 Management API client."""

    @pytest.mark.asyncio
    async def test_get_management_token_success(self):
        """Test getting management token."""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "mgmt-token",
                "expires_in": 86400,
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            client = Auth0Client()
            token = await client.get_management_token()

            assert token == "mgmt-token"

    @pytest.mark.asyncio
    async def test_get_management_token_cached(self):
        """Test management token caching."""
        client = Auth0Client()
        client.management_token = "cached-token"
        client.token_expires_at = datetime.utcnow() + timedelta(hours=1)

        token = await client.get_management_token()

        assert token == "cached-token"

    @pytest.mark.asyncio
    async def test_get_user_success(self):
        """Test getting user from Auth0."""
        with patch.object(Auth0Client, "get_management_token", return_value="test-token"):
            with patch("httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "user_id": "auth0|123",
                    "email": "user@example.com",
                }

                mock_client_instance = AsyncMock()
                mock_client_instance.get.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_client_instance

                client = Auth0Client()
                user = await client.get_user("auth0|123")

                assert user["user_id"] == "auth0|123"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self):
        """Test getting non-existent user."""
        with patch.object(Auth0Client, "get_management_token", return_value="test-token"):
            with patch("httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 404

                mock_client_instance = AsyncMock()
                mock_client_instance.get.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_client_instance

                client = Auth0Client()

                with pytest.raises(HTTPException) as exc_info:
                    await client.get_user("auth0|nonexistent")

                assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user_success(self):
        """Test updating user in Auth0."""
        with patch.object(Auth0Client, "get_management_token", return_value="test-token"):
            with patch("httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"email": "updated@example.com"}

                mock_client_instance = AsyncMock()
                mock_client_instance.patch.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_client_instance

                client = Auth0Client()
                result = await client.update_user("auth0|123", {"email": "updated@example.com"})

                assert result["email"] == "updated@example.com"

    @pytest.mark.asyncio
    async def test_get_user_permissions(self):
        """Test getting user permissions."""
        with patch.object(Auth0Client, "get_management_token", return_value="test-token"):
            with patch("httpx.AsyncClient") as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = [
                    {"permission_name": "read:data"},
                    {"permission_name": "write:data"},
                ]

                mock_client_instance = AsyncMock()
                mock_client_instance.get.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_client_instance

                client = Auth0Client()
                permissions = await client.get_user_permissions("auth0|123")

                assert "read:data" in permissions
                assert "write:data" in permissions


# ============================================================================
# JWT VERIFICATION TESTS
# ============================================================================


class TestJWTVerification:
    """Test JWT verification functions."""

    def test_verify_jwt_token_missing_kid(self, mock_jwks):
        """Test verification fails without key ID."""
        with patch("security.auth0_integration.get_auth0_public_key", return_value=mock_jwks):
            # Create token without kid
            token = jwt.encode(
                {"sub": "test", "aud": AUTH0_AUDIENCE, "iss": f"https://{AUTH0_DOMAIN}/"},
                "secret",
                algorithm="HS256",
            )

            with pytest.raises(HTTPException) as exc_info:
                verify_jwt_token(token)

            assert exc_info.value.status_code == 401

    def test_verify_jwt_token_key_not_found(self, mock_jwks):
        """Test verification fails when key is not in JWKS."""
        with patch("security.auth0_integration.get_auth0_public_key", return_value=mock_jwks):
            # Token with different kid than what's in JWKS
            token = jwt.encode(
                {"sub": "test"},
                "secret",
                algorithm="HS256",
                headers={"kid": "different-key-id"},
            )

            with pytest.raises(HTTPException) as exc_info:
                verify_jwt_token(token)

            assert exc_info.value.status_code == 401


# ============================================================================
# DEVSKYY JWT TESTS
# ============================================================================


class TestDevSkyyJWT:
    """Test DevSkyy JWT token functions."""

    def test_create_devskyy_jwt_token(self):
        """Test creating DevSkyy JWT token."""
        with patch.dict(os.environ, {"SECRET_KEY": "test-secret"}):
            user_data = {
                "sub": "auth0|123",
                "email": "test@example.com",
                "name": "Test User",
            }

            token = create_devskyy_jwt_token(user_data)

            assert isinstance(token, str)
            assert len(token) > 0

    def test_create_devskyy_jwt_token_with_expiry(self):
        """Test creating token with custom expiry."""
        with patch.dict(os.environ, {"SECRET_KEY": "test-secret"}):
            user_data = {"sub": "auth0|123"}
            expires = timedelta(hours=2)

            token = create_devskyy_jwt_token(user_data, expires_delta=expires)

            # Decode and verify expiry
            payload = jwt.decode(token, "test-secret", algorithms=["HS256"], options={"verify_aud": False})
            expected_exp = int((datetime.utcnow() + expires).timestamp())
            assert abs(payload["exp"] - expected_exp) < 5  # 5 second tolerance

    def test_create_devskyy_jwt_token_no_secret(self):
        """Test token creation fails without secret key."""
        with patch.dict(os.environ, {"SECRET_KEY": ""}, clear=True):
            with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", None):
                with pytest.raises(ValueError):
                    create_devskyy_jwt_token({"sub": "test"})

    def test_create_devskyy_refresh_token(self):
        """Test creating refresh token."""
        with patch.dict(os.environ, {"SECRET_KEY": "test-secret"}):
            user_data = {"sub": "auth0|123"}

            token = create_devskyy_refresh_token(user_data)

            assert isinstance(token, str)
            assert len(token) > 0

    def test_verify_devskyy_jwt_token_success(self):
        """Test successful DevSkyy token verification."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": "devskyy-platform",
                "aud": "devskyy-api",
            }
            token = jwt.encode(payload, secret, algorithm="HS256")

            result = verify_devskyy_jwt_token(token)

            assert result["sub"] == "auth0|123"
            assert result["iss"] == "devskyy-platform"

    def test_verify_devskyy_jwt_token_expired(self):
        """Test expired token verification."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": "devskyy-platform",
                "aud": "devskyy-api",
            }
            token = jwt.encode(payload, secret, algorithm="HS256")

            with pytest.raises(HTTPException) as exc_info:
                verify_devskyy_jwt_token(token)

            assert exc_info.value.status_code == 401

    def test_verify_devskyy_jwt_token_invalid_signature(self):
        """Test token with invalid signature."""
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", "correct-secret"):
            payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iss": "devskyy-platform",
                "aud": "devskyy-api",
            }
            token = jwt.encode(payload, "wrong-secret", algorithm="HS256")

            with pytest.raises(HTTPException) as exc_info:
                verify_devskyy_jwt_token(token)

            assert exc_info.value.status_code == 401


# ============================================================================
# DEPENDENCY TESTS
# ============================================================================


class TestDependencies:
    """Test FastAPI dependencies."""

    @pytest.mark.asyncio
    async def test_get_current_admin_user_success(self, mock_admin_user):
        """Test getting current admin user."""
        result = await get_current_admin_user(mock_admin_user)

        assert result.role == "admin"

    @pytest.mark.asyncio
    async def test_get_current_admin_user_forbidden(self, mock_auth0_user):
        """Test non-admin user is forbidden."""
        with pytest.raises(HTTPException) as exc_info:
            await get_current_admin_user(mock_auth0_user)

        assert exc_info.value.status_code == 403
        assert "Admin access required" in exc_info.value.detail

    def test_require_permissions_success(self, mock_auth0_user):
        """Test permission check passes."""
        checker = require_permissions(["read:data"])
        result = checker(mock_auth0_user)

        assert result.sub == mock_auth0_user.sub

    def test_require_permissions_missing(self, mock_auth0_user):
        """Test permission check fails for missing permissions."""
        checker = require_permissions(["admin:all", "read:data"])

        with pytest.raises(HTTPException) as exc_info:
            checker(mock_auth0_user)

        assert exc_info.value.status_code == 403
        assert "Missing required permissions" in exc_info.value.detail

    def test_require_scope_success(self, mock_token_payload):
        """Test scope check passes."""
        with patch("security.auth0_integration.verify_jwt_token", return_value=mock_token_payload):
            checker = require_scope("read:data")
            credentials = MagicMock()
            credentials.credentials = "test-token"

            result = checker(credentials)

            assert result.sub == mock_token_payload.sub

    def test_require_scope_missing(self, mock_token_payload):
        """Test scope check fails for missing scope."""
        with patch("security.auth0_integration.verify_jwt_token", return_value=mock_token_payload):
            checker = require_scope("admin:delete")
            credentials = MagicMock()
            credentials.credentials = "test-token"

            with pytest.raises(HTTPException) as exc_info:
                checker(credentials)

            assert exc_info.value.status_code == 403


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================


class TestUtilityFunctions:
    """Test utility functions."""

    @pytest.mark.asyncio
    async def test_log_auth_event(self):
        """Test authentication event logging."""
        with patch("security.auth0_integration.logger") as mock_logger:
            request = MagicMock()
            request.client.host = "127.0.0.1"
            request.headers.get.return_value = "Mozilla/5.0"

            await log_auth_event(
                event_type="login",
                user_id="auth0|123",
                request=request,
                details={"method": "password"},
            )

            mock_logger.info.assert_called_once()
            log_message = mock_logger.info.call_args[0][0]
            assert "AUTH_EVENT" in log_message
            assert "login" in log_message

    @pytest.mark.asyncio
    async def test_log_auth_event_without_request(self):
        """Test logging without request context."""
        with patch("security.auth0_integration.logger") as mock_logger:
            await log_auth_event(event_type="logout", user_id="auth0|123")

            mock_logger.info.assert_called_once()

    def test_get_auth0_login_url(self):
        """Test generating login URL."""
        redirect_uri = "https://example.com/callback"

        url = get_auth0_login_url(redirect_uri, state="test-state")

        assert AUTH0_DOMAIN in url
        assert "authorize" in url
        assert "response_type=code" in url


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================


class TestHealthCheck:
    """Test Auth0 health check."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self):
        """Test health check when services are healthy."""
        with patch("httpx.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            with patch.object(Auth0Client, "get_management_token", return_value="token"):
                result = await auth0_health_check()

                assert result["status"] == "healthy"
                assert result["jwks_endpoint"] == "healthy"
                assert result["domain"] == AUTH0_DOMAIN

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self):
        """Test health check when JWKS is unavailable."""
        with patch("httpx.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_get.return_value = mock_response

            result = await auth0_health_check()

            assert result["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_health_check_exception(self):
        """Test health check when exception occurs."""
        with patch("httpx.get", side_effect=Exception("Connection failed")):
            result = await auth0_health_check()

            assert result["status"] == "unhealthy"
            assert "error" in result


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests for Auth0 authentication flow."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete authentication flow."""
        # Step 1: Generate authorization URL
        redirect_uri = "https://example.com/callback"
        auth_url = auth0_oauth_client.get_authorization_url(redirect_uri, state="test")

        assert "authorize" in auth_url
        assert redirect_uri in auth_url or "redirect_uri" in auth_url

        # Step 2: Mock token exchange
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "access-token",
                "id_token": "id-token",
                "token_type": "Bearer",
                "expires_in": 86400,
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            tokens = await auth0_oauth_client.exchange_code_for_token(
                code="auth-code",
                redirect_uri=redirect_uri,
            )

            assert tokens["access_token"] == "access-token"

        # Step 3: Mock user info retrieval
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "sub": "auth0|123",
                "email": "user@example.com",
                "name": "Test User",
                "email_verified": True,
            }

            mock_client_instance = AsyncMock()
            mock_client_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance

            user_info = await auth0_oauth_client.get_user_info("access-token")

            assert user_info["sub"] == "auth0|123"
            assert user_info["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_token_refresh_flow(self):
        """Test token refresh flow with DevSkyy tokens."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            # Create initial access token
            user_data = {
                "sub": "auth0|123",
                "email": "user@example.com",
            }

            access_token = create_devskyy_jwt_token(user_data, timedelta(minutes=15))
            refresh_token = create_devskyy_refresh_token(user_data)

            # Verify both tokens were created
            assert access_token is not None
            assert refresh_token is not None

            # Verify access token
            payload = verify_devskyy_jwt_token(access_token)
            assert payload["sub"] == "auth0|123"

            # Verify refresh token
            refresh_payload = jwt.decode(
                refresh_token,
                secret,
                algorithms=["HS256"],
                options={"verify_aud": False},
            )
            assert refresh_payload["token_type"] == "refresh"
            assert refresh_payload["sub"] == "auth0|123"


# ============================================================================
# SECURITY TESTS
# ============================================================================


class TestSecurity:
    """Security-focused tests."""

    def test_token_not_leaked_in_error_messages(self):
        """Ensure tokens are not leaked in error messages."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            with pytest.raises(HTTPException) as exc_info:
                verify_devskyy_jwt_token("invalid-token")

            # Token should not appear in error detail
            assert "invalid-token" not in str(exc_info.value.detail)

    def test_expired_token_rejected(self):
        """Test that expired tokens are properly rejected."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            expired_payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": "devskyy-platform",
                "aud": "devskyy-api",
            }
            expired_token = jwt.encode(expired_payload, secret, algorithm="HS256")

            with pytest.raises(HTTPException) as exc_info:
                verify_devskyy_jwt_token(expired_token)

            assert exc_info.value.status_code == 401

    def test_wrong_issuer_rejected(self):
        """Test that tokens with wrong issuer are rejected."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            wrong_issuer_payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": "wrong-issuer",
                "aud": "devskyy-api",
            }
            token = jwt.encode(wrong_issuer_payload, secret, algorithm="HS256")

            with pytest.raises(HTTPException):
                verify_devskyy_jwt_token(token)

    def test_wrong_audience_rejected(self):
        """Test that tokens with wrong audience are rejected."""
        secret = "test-secret"
        with patch("security.auth0_integration.DEVSKYY_SECRET_KEY", secret):
            wrong_audience_payload = {
                "sub": "auth0|123",
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": "devskyy-platform",
                "aud": "wrong-audience",
            }
            token = jwt.encode(wrong_audience_payload, secret, algorithm="HS256")

            with pytest.raises(HTTPException):
                verify_devskyy_jwt_token(token)
