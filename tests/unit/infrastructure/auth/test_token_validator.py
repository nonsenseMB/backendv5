import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from src.infrastructure.auth.token_validator import TokenValidator
from src.infrastructure.auth.config import AuthentikConfig
from src.infrastructure.auth.exceptions import AuthentikValidationError


# Test private key in PEM format
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAu6K9xdhzCtFhPeOYEF7gP6odNFtqiprXUavUzB8zeW2CkPTB
r1d5RNA0dy0wf0ohBAXLjZZG8SkJyEInN0MEr4Gg/Bw9LlzbnYW7/A77P086KMoA
77xKmWkdKMh7Cm5WZx26Gdr8Fq+SfMpiFfctFLIIbjO3zpU/c0elQw8Yk3IszGsJ
EuSOOo5tFobz6PiQCp5So9/m/7aWbkgQfPWm2EF9jojtZwr4ZmQtEJxNarxENWZv
O77jAkHkyEI3PA4sA05oavPMEgtuHT6tV/3cav9kfcQQ042JAf46jgSOAKQzeARE
DhSvy5Z/piD3Uh0px7edcSvszTdX3u9VIxFEgwIDAQABAoIBACKlUQ8oAU39DUyF
Kr3TFusKeSwCuTBwmNNuu/MYy8NfEh2748uBhlXLb/SVdn/6axA4FbbGCcFbx3+f
n2gXytSxRc1nVXCrGq4CVIydI400DtQbQIMDrG6ZNxYhtn5dkzylA4jko2l47751
DBlsM3m/yci3afgOHNInZ39zWSFYQPawOxaeIneUNFXFCHHvD49HTRetpNitrLKP
vXPQMMY3II+jax0vJM4R5vUYXWUKoCDDFR3BbNLrHL3i9WFVyuYFxuG2uPFsz2z6
hEHH7bgkT8rq3F0pC19bY9OYExv4Pnk4t8UtOHPp/3vKAtEQmwLOOxYXCflNFCFN
lrkzpjECgYEA+yqrt3gBsikVMRx/sYEFFtec2AgJPASl7UtDFHvC670R1cigILQw
Oay6JWXlPt4uWURp6DgjHYcc6yjOk1vIx/LS/Aci2wXjCECUFk9elgsa3lkriMmB
QGYcoioWRValZKvTWoSEpIONF4qx5t4MoH6ja18dtR8IMpJBp4l/JJkCgYEAvz8Y
nrKzyZA+MRUOmII8gx0nwxu6Twh3bNFvetGgpCpQc2XHvTitY2ogZKT0Oj9LfJDq
dp9HWX9KztNk7nwIoMNFsObGlTArV3WvBxDTlNEddEh2GxbRL4gK6FuOLoPjIJhg
s8NLrZTyopsjRfQWX589PTZrNvmfbcT5KNreh3sCgYArxyk9BlbNVenSsJP1PXbE
n3pAEU6CvpCpRqf/hv7XlhHowFpguOd69gdQA22swo8zkgAfsME2IVnCB0/SUXoy
l7l8okXKBUGoK5FkPhtPbcoWHVbANdcogWPWRB2zokGbxXNGYLi58BAEnXEau3NZ
+hjD20VTT4BfSCzXZdjaaQKBgCYaKwyLK/ivjUR4HoVSBT5WE7Lylkbit/BtNZmx
pCCw8YBcOdRAM4NIBJYoqyPjsmVp9dyWVT/GdaAJS+WbvphQ71SUVeIpS6lMIAf3
WUAf/Y9KVIWHITwoDYxHmWc5DYpT8Yg/E5fMwh6VbAym2cJJVokYi3nTd+kFwmJa
YNV7AoGAeutUFMq5ixQ9XauRHz9BgNmT+wNjr8cD6V02pw/n5BRkYaPj8U+ujf2V
6ovYmnDxVRA4jxkHnXjJYtile3dWf7S+d6YTpQBeNr+LwUTkwVR8AY+m/hdq91aK
NXg1WwAGHGYlRscCAh52v6minITpqQ+8W/lOk5n14uF7XI5pD6U=
-----END RSA PRIVATE KEY-----"""

# Test public key in PEM format
TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu6K9xdhzCtFhPeOYEF7g
P6odNFtqiprXUavUzB8zeW2CkPTBr1d5RNA0dy0wf0ohBAXLjZZG8SkJyEInN0ME
r4Gg/Bw9LlzbnYW7/A77P086KMoA77xKmWkdKMh7Cm5WZx26Gdr8Fq+SfMpiFfct
FLIIbjO3zpU/c0elQw8Yk3IszGsJEuSOOo5tFobz6PiQCp5So9/m/7aWbkgQfPWm
2EF9jojtZwr4ZmQtEJxNarxENWZvO77jAkHkyEI3PA4sA05oavPMEgtuHT6tV/3c
av9kfcQQ042JAf46jgSOAKQzeAREDhSvy5Z/piD3Uh0px7edcSvszTdX3u9VIxFE
gwIDAQAB
-----END PUBLIC KEY-----"""


def create_test_token(
    claims: dict,
    kid: str = "test-key-1",
    algorithm: str = "RS256",
    expires_in: int = 3600
) -> str:
    """Create a test JWT token."""
    now = datetime.now(timezone.utc)
    
    # Set default claims
    default_claims = {
        "iss": "http://127.0.0.1:9000/application/o/nai-platform/",
        "sub": "test-user",
        "aud": "nai-platform",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "jti": "test-jti-123"
    }
    
    # Merge with provided claims
    default_claims.update(claims)
    
    # Create token using private key
    return jwt.encode(
        default_claims,
        TEST_PRIVATE_KEY,
        algorithm=algorithm,
        headers={"kid": kid}
    )


@pytest.fixture
def config():
    return AuthentikConfig(
        authentik_url="http://127.0.0.1:9000",
        authentik_token="test-token",
        jwt_audience="nai-platform",
        jwt_algorithm="RS256"
    )


@pytest.fixture
def mock_jwks_cache():
    cache = AsyncMock()
    # Return the public key in PEM format for jose
    cache.get_signing_key = AsyncMock(return_value=TEST_PUBLIC_KEY)
    cache.refresh = AsyncMock()
    return cache


@pytest.mark.asyncio
class TestTokenValidator:
    
    async def test_initialization(self, config):
        validator = TokenValidator(config)
        assert validator.config == config
        assert validator.algorithm == "RS256"
        assert validator.expected_audience == "nai-platform"
        assert validator.expected_issuer == "http://127.0.0.1:9000/application/o/nai-platform/"
    
    async def test_validate_valid_token(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Create a valid token
        token = create_test_token({"email": "test@example.com"})
        
        # Validate
        claims = await validator.validate_token(token)
        
        assert claims["sub"] == "test-user"
        assert claims["email"] == "test@example.com"
        assert claims["aud"] == "nai-platform"
        
        # Verify JWKS cache was called
        mock_jwks_cache.get_signing_key.assert_called_once_with("test-key-1")
    
    async def test_validate_expired_token(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Create an expired token
        token = create_test_token({}, expires_in=-3600)  # Expired 1 hour ago
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "Token has expired" in str(exc_info.value)
    
    async def test_validate_token_wrong_audience(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Create token with wrong audience
        token = create_test_token({"aud": "wrong-audience"})
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "Invalid token claims" in str(exc_info.value)
    
    async def test_validate_token_wrong_issuer(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Create token with wrong issuer
        token = create_test_token({"iss": "https://wrong-issuer.com"})
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "Invalid token claims" in str(exc_info.value)
    
    async def test_validate_token_missing_kid(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Create token without kid in header
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": "test-user",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(hours=1)).timestamp())
            },
            TEST_PRIVATE_KEY,
            algorithm="RS256"
        )
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "Token missing 'kid' in header" in str(exc_info.value)
    
    async def test_validate_token_key_not_found(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # Mock cache to return None (key not found)
        mock_jwks_cache.get_signing_key.return_value = None
        
        token = create_test_token({})
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "No signing key found" in str(exc_info.value)
        
        # Verify refresh was attempted
        mock_jwks_cache.refresh.assert_called_once()
    
    async def test_validate_token_missing_required_claims(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        token = create_test_token({})
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token, required_claims=["email", "groups"])
        
        assert "missing required key" in str(exc_info.value)
    
    async def test_validate_token_not_yet_valid(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        validator.leeway = 5  # Small leeway for testing
        
        # Create token that's not valid yet
        now = datetime.now(timezone.utc)
        future_time = now + timedelta(minutes=10)
        
        token = create_test_token({
            "nbf": int(future_time.timestamp())
        })
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_token(token)
        
        assert "not yet valid" in str(exc_info.value)
    
    async def test_get_token_info(self, config):
        validator = TokenValidator(config)
        
        token = create_test_token({"email": "test@example.com"})
        
        info = await validator.get_token_info(token)
        
        assert info["subject"] == "test-user"
        assert info["issuer"] == "http://127.0.0.1:9000/application/o/nai-platform/"
        assert info["audience"] == "nai-platform"
        assert info["kid"] == "test-key-1"
        assert info["algorithm"] == "RS256"
        assert info["is_expired"] is False
        assert info["token_age_seconds"] is not None
        assert info["time_to_expiry_seconds"] > 0
    
    async def test_validate_access_token(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        token = create_test_token({})
        
        claims = await validator.validate_access_token(token)
        
        assert claims["sub"] == "test-user"
        assert "iat" in claims
    
    async def test_validate_id_token(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        # ID token requires auth_time
        token = create_test_token({
            "auth_time": int(datetime.now(timezone.utc).timestamp()),
            "nonce": "test-nonce"
        })
        
        claims = await validator.validate_id_token(token)
        
        assert claims["sub"] == "test-user"
        assert "auth_time" in claims
        assert claims["nonce"] == "test-nonce"
    
    async def test_validate_id_token_empty_nonce(self, config, mock_jwks_cache):
        validator = TokenValidator(config, jwks_cache=mock_jwks_cache)
        
        token = create_test_token({
            "auth_time": int(datetime.now(timezone.utc).timestamp()),
            "nonce": ""  # Empty nonce
        })
        
        with pytest.raises(AuthentikValidationError) as exc_info:
            await validator.validate_id_token(token)
        
        assert "ID token has empty nonce" in str(exc_info.value)