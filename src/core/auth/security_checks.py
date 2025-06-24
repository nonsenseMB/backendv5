"""
Security checks for application startup.
Validates configuration and ensures security requirements are met.
"""

import sys

import httpx

from src.core.config import settings
from src.core.logging import get_logger
from src.core.logging.audit import AuditEventType, AuditSeverity, log_audit_event

logger = get_logger(__name__)


class SecurityCheckError(Exception):
    """Raised when a security check fails"""
    pass


class SecurityChecker:
    """Performs security checks at application startup"""

    def __init__(self):
        self.checks_passed: list[str] = []
        self.checks_failed: list[tuple[str, str]] = []

    async def run_all_checks(self) -> bool:
        """
        Run all security checks.
        Returns True if all checks pass, False otherwise.
        """
        logger.info("Starting security checks")

        # List of checks to run
        checks = [
            ("Password Authentication", self._check_password_auth_disabled, False),
            ("Device Authentication", self._check_device_auth_required, False),
            ("Authentik Connectivity", self._check_authentik_connectivity, True),
            ("JWT Configuration", self._check_jwt_configuration, False),
            ("WebAuthn Configuration", self._check_webauthn_configuration, False),
            ("Session Configuration", self._check_session_configuration, False),
            ("CORS Configuration", self._check_cors_configuration, False),
            ("SSL/TLS Configuration", self._check_ssl_configuration, False),
        ]

        # Run each check
        for check_name, check_func, is_async in checks:
            try:
                if is_async:
                    result = await check_func()
                else:
                    result = check_func()

                if result:
                    self.checks_passed.append(check_name)
                    logger.info(f"Security check passed: {check_name}")
                else:
                    self.checks_failed.append((check_name, "Check returned False"))
                    logger.error(f"Security check failed: {check_name}")
            except Exception as e:
                self.checks_failed.append((check_name, str(e)))
                logger.error(f"Security check failed: {check_name}", error=str(e))

        # Log audit event
        log_audit_event(
            event_type=AuditEventType.SECURITY_CHECK,
            severity=AuditSeverity.HIGH if self.checks_failed else AuditSeverity.LOW,
            details={
                "checks_passed": len(self.checks_passed),
                "checks_failed": len(self.checks_failed),
                "failed_checks": [{"name": name, "error": error} for name, error in self.checks_failed]
            }
        )

        # Summary
        total_checks = len(self.checks_passed) + len(self.checks_failed)
        logger.info(
            f"Security checks completed: {len(self.checks_passed)}/{total_checks} passed"
        )

        return len(self.checks_failed) == 0

    def _check_password_auth_disabled(self) -> bool:
        """Ensure password authentication is disabled"""
        if settings.PASSWORD_AUTH_ENABLED:
            raise SecurityCheckError(
                "Password authentication must be disabled. "
                "Set PASSWORD_AUTH_ENABLED=false in environment."
            )
        return True

    def _check_device_auth_required(self) -> bool:
        """Ensure device authentication is required"""
        if not settings.DEVICE_AUTH_REQUIRED:
            raise SecurityCheckError(
                "Device authentication must be required. "
                "Set DEVICE_AUTH_REQUIRED=true in environment."
            )
        return True

    async def _check_authentik_connectivity(self) -> bool:
        """Check connectivity to Authentik server"""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(settings.AUTHENTIK_TIMEOUT_SECONDS),
                verify=settings.AUTHENTIK_VERIFY_SSL
            ) as client:
                # Try to access the well-known endpoint
                response = await client.get(
                    f"{settings.AUTHENTIK_URL}/.well-known/openid-configuration"
                )

                if response.status_code != 200:
                    raise SecurityCheckError(
                        f"Authentik server returned status {response.status_code}"
                    )

                # Verify it's actually Authentik
                data = response.json()
                if "issuer" not in data:
                    raise SecurityCheckError(
                        "Invalid OpenID configuration response from Authentik"
                    )

                logger.info("Authentik connectivity verified", issuer=data.get("issuer"))
                return True

        except httpx.ConnectError:
            raise SecurityCheckError(
                f"Cannot connect to Authentik at {settings.AUTHENTIK_URL}. "
                "Please ensure Authentik is running and accessible."
            )
        except httpx.TimeoutException:
            raise SecurityCheckError(
                f"Timeout connecting to Authentik at {settings.AUTHENTIK_URL}"
            )
        except Exception as e:
            raise SecurityCheckError(f"Error connecting to Authentik: {str(e)}")

    def _check_jwt_configuration(self) -> bool:
        """Validate JWT configuration"""
        # Check algorithm
        if settings.JWT_ALGORITHM not in ["RS256", "ES256"]:
            logger.warning(
                "JWT algorithm is not RS256 or ES256. "
                "Consider using asymmetric algorithms for better security."
            )

        # Check token expiration times
        if settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES > 60:
            logger.warning(
                "Access token expiration is longer than 60 minutes. "
                "Consider shorter expiration for better security."
            )

        if settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS > 90:
            logger.warning(
                "Refresh token expiration is longer than 90 days. "
                "Consider shorter expiration for better security."
            )

        return True

    def _check_webauthn_configuration(self) -> bool:
        """Validate WebAuthn configuration"""
        if settings.DEVICE_AUTH_REQUIRED:
            # Check user verification
            if settings.WEBAUTHN_USER_VERIFICATION != "required":
                logger.warning(
                    "WebAuthn user verification is not set to 'required'. "
                    "Consider requiring user verification for better security."
                )

            # Check RP ID
            if settings.WEBAUTHN_RP_ID == "localhost" and settings.APP_ENV == "production":
                raise SecurityCheckError(
                    "WebAuthn RP ID cannot be 'localhost' in production. "
                    "Set WEBAUTHN_RP_ID to your domain."
                )

        return True

    def _check_session_configuration(self) -> bool:
        """Validate session configuration"""
        # Check session timeout
        if settings.SESSION_TIMEOUT_MINUTES > 1440:  # 24 hours
            logger.warning(
                "Session timeout is longer than 24 hours. "
                "Consider shorter timeout for better security."
            )

        # Check MFA enforcement
        if not settings.ENFORCE_MFA and settings.APP_ENV == "production":
            logger.warning(
                "Multi-factor authentication is not enforced in production. "
                "Consider setting ENFORCE_MFA=true."
            )

        return True

    def _check_cors_configuration(self) -> bool:
        """Validate CORS configuration"""
        if settings.APP_ENV == "production":
            # Check for wildcards
            if "*" in settings.CORS_ORIGINS:
                raise SecurityCheckError(
                    "CORS origins cannot contain wildcards in production. "
                    "Specify exact allowed origins."
                )

            # Check for localhost
            for origin in settings.CORS_ORIGINS:
                if "localhost" in origin or "127.0.0.1" in origin:
                    logger.warning(
                        f"CORS origin '{origin}' contains localhost/127.0.0.1 in production"
                    )

        return True

    def _check_ssl_configuration(self) -> bool:
        """Validate SSL/TLS configuration"""
        if settings.APP_ENV == "production":
            # Check Authentik SSL verification
            if not settings.AUTHENTIK_VERIFY_SSL:
                raise SecurityCheckError(
                    "SSL verification for Authentik must be enabled in production. "
                    "Set AUTHENTIK_VERIFY_SSL=true."
                )

            # Check Redis SSL
            if "redis://" in settings.REDIS_URL and "localhost" not in settings.REDIS_URL:
                logger.warning(
                    "Redis connection is not using SSL. "
                    "Consider using rediss:// for encrypted connections."
                )

        return True

    def get_summary(self) -> str:
        """Get a summary of security check results"""
        lines = ["Security Check Summary:", "=" * 50]

        if self.checks_passed:
            lines.append("\nPassed checks:")
            for check in self.checks_passed:
                lines.append(f"  ✓ {check}")

        if self.checks_failed:
            lines.append("\nFailed checks:")
            for check, error in self.checks_failed:
                lines.append(f"  ✗ {check}: {error}")

        lines.append("=" * 50)
        return "\n".join(lines)


async def run_startup_security_checks() -> None:
    """
    Run security checks at application startup.
    Exits the application if critical checks fail.
    """
    checker = SecurityChecker()

    try:
        success = await checker.run_all_checks()

        # Print summary
        print(checker.get_summary())

        if not success:
            logger.error("Security checks failed. Application startup aborted.")
            log_audit_event(
                event_type=AuditEventType.SECURITY_ALERT,
                severity=AuditSeverity.CRITICAL,
                details={
                    "message": "Application startup aborted due to failed security checks",
                    "failed_checks": checker.checks_failed
                }
            )
            sys.exit(1)
        else:
            logger.info("All security checks passed. Application startup continuing.")

    except Exception as e:
        logger.error("Unexpected error during security checks", error=str(e))
        log_audit_event(
            event_type=AuditEventType.SECURITY_ALERT,
            severity=AuditSeverity.CRITICAL,
            details={
                "message": "Security check system failure",
                "error": str(e)
            }
        )
        sys.exit(1)


def validate_no_passwords_in_database() -> bool:
    """
    Validate that no password fields exist in the database schema.
    This should be called after database initialization.
    """
    # This is a placeholder - actual implementation would check database schema
    # For now, we'll document this requirement
    logger.info(
        "Password field validation skipped - ensure no password fields in database schema"
    )
    return True
