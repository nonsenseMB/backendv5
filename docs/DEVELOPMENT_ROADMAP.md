# nAI Backend v5 - Detaillierter Entwicklungsauftrag

## Executive Summary

Basierend auf der Analyse der vorhandenen Dokumentation aus dem tmp-Verzeichnis wurde ein umfassender Entwicklungsplan für die Implementierung eines hochsicheren, multi-tenant-fähigen Authentifizierungs- und Autorisierungssystems erstellt. Dieser Plan priorisiert Sicherheit, GDPR-Compliance und Enterprise-Readiness.

### ⚠️ WICHTIGE ARCHITEKTUR-ENTSCHEIDUNGEN:

1. **KEINE LOKALE AUTHENTIFIZIERUNG**: Alle Authentifizierung erfolgt über Authentik
2. **PASSWORDLESS ONLY**: Ausschließlich Device-basierte Authentifizierung (WebAuthn, Passkeys, Certificates)
3. **KEINE PASSWORT-FELDER**: Weder in der Datenbank noch in der API
4. **AUTHENTIK ALS SINGLE SOURCE OF TRUTH**: Für alle Authentifizierungs-Belange

## Inhaltsverzeichnis

1. [Sicherheitsarchitektur](#sicherheitsarchitektur)
2. [Authentifizierungssystem](#authentifizierungssystem)
3. [Multi-Tenant-Architektur](#multi-tenant-architektur)
4. [API-Sicherheit](#api-sicherheit)
5. [Datenbank-Sicherheit](#datenbank-sicherheit)
6. [Infrastruktur-Sicherheit](#infrastruktur-sicherheit)
7. [Compliance & Audit](#compliance--audit)
8. [Entwicklungsphasen](#entwicklungsphasen)
9. [Technische Spezifikationen](#technische-spezifikationen)
10. [Risikobewertung](#risikobewertung)

---

## 1. Sicherheitsarchitektur

### 1.1 Zero-Trust-Prinzipien

#### Anforderungen:
- **Niemals vertrauen, immer verifizieren**: Jede Anfrage muss authentifiziert und autorisiert werden
- **Principle of Least Privilege**: Minimale Berechtigungen als Standard
- **Defense in Depth**: Mehrschichtige Sicherheitsmechanismen

#### Implementierungsdetails:

```python
# src/core/security/zero_trust.py
from typing import Optional, List
from datetime import datetime, timedelta
import hashlib
import hmac

class ZeroTrustValidator:
    """
    Implementiert Zero-Trust-Validierung für alle Anfragen.
    """
    
    def __init__(self):
        self.risk_engine = RiskAssessmentEngine()
        self.policy_engine = PolicyEngine()
        self.context_analyzer = ContextAnalyzer()
    
    async def validate_request(
        self,
        request: Request,
        user_context: UserContext,
        resource: str,
        action: str
    ) -> ValidationResult:
        """
        Vollständige Zero-Trust-Validierung einer Anfrage.
        """
        # 1. Identitätsverifizierung
        identity_score = await self._verify_identity(user_context)
        
        # 2. Geräteverifizierung
        device_score = await self._verify_device(request)
        
        # 3. Netzwerkverifizierung
        network_score = await self._verify_network(request)
        
        # 4. Verhaltensanalyse
        behavior_score = await self._analyze_behavior(user_context)
        
        # 5. Risikoberechnung
        risk_score = self.risk_engine.calculate_risk(
            identity_score,
            device_score,
            network_score,
            behavior_score
        )
        
        # 6. Policy-Entscheidung
        decision = self.policy_engine.evaluate(
            user_context,
            resource,
            action,
            risk_score
        )
        
        # 7. Adaptive Authentifizierung bei erhöhtem Risiko
        if decision.requires_mfa and not user_context.has_recent_mfa:
            return ValidationResult(
                allowed=False,
                reason="MFA_REQUIRED",
                challenge_type="mfa"
            )
        
        return decision
```

### 1.2 Kryptographie-Standards

#### Anforderungen:
- **Moderne Algorithmen**: Nur zugelassene, sichere Algorithmen verwenden
- **Key Management**: Sicheres Schlüsselmanagement mit Rotation
- **Quantum-Ready**: Vorbereitung auf Post-Quantum-Kryptographie

#### Implementierung:

```python
# src/core/security/crypto.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class CryptoManager:
    """
    Zentrales Kryptographie-Management mit Best Practices.
    """
    
    # Algorithmus-Whitelist
    ALLOWED_HASH_ALGORITHMS = {
        "SHA256": hashes.SHA256,
        "SHA384": hashes.SHA384,
        "SHA512": hashes.SHA512,
        "SHA3_256": hashes.SHA3_256,
        "SHA3_512": hashes.SHA3_512
    }
    
    ALLOWED_KDF_ITERATIONS = {
        "minimum": 100_000,
        "recommended": 600_000,
        "high_security": 1_000_000
    }
    
    def __init__(self, security_level: str = "recommended"):
        self.security_level = security_level
        self.key_rotation_scheduler = KeyRotationScheduler()
        
    async def encrypt_sensitive_data(
        self,
        plaintext: bytes,
        context: EncryptionContext
    ) -> EncryptedData:
        """
        Verschlüsselt sensitive Daten mit AES-GCM.
        """
        # Generate unique nonce for each encryption
        nonce = secrets.token_bytes(12)
        
        # Get or generate data encryption key
        dek = await self._get_data_encryption_key(context)
        
        # Encrypt with authenticated encryption
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext,
            context.to_aad()  # Additional authenticated data
        )
        
        # Log encryption event for audit
        await self._audit_encryption_event(context)
        
        return EncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            key_id=context.key_id,
            algorithm="AES-256-GCM",
            timestamp=datetime.utcnow()
        )
```

### 1.3 Secrets Management

#### Anforderungen:
- **Keine Hardcoded Secrets**: Alle Secrets extern verwalten
- **Rotation**: Automatische Secret-Rotation
- **Audit Trail**: Vollständige Nachverfolgbarkeit

#### Implementierung:

```python
# src/core/security/secrets.py
from hvac import Client as VaultClient
import boto3
from azure.keyvault.secrets import SecretClient

class SecretsManager:
    """
    Multi-Provider Secrets Management mit Fallback.
    """
    
    def __init__(self, providers: List[SecretsProvider]):
        self.providers = providers
        self.cache = SecureCache(ttl=300)  # 5 Minuten Cache
        self.audit_logger = get_logger("secrets_audit")
        
    async def get_secret(
        self,
        secret_name: str,
        version: Optional[str] = None,
        context: Optional[RequestContext] = None
    ) -> SecretValue:
        """
        Holt ein Secret mit Multi-Provider-Support.
        """
        # Check cache first
        cache_key = f"{secret_name}:{version or 'latest'}"
        if cached := self.cache.get(cache_key):
            return cached
            
        # Try providers in order
        for provider in self.providers:
            try:
                secret = await provider.get_secret(secret_name, version)
                
                # Validate secret
                if not self._validate_secret(secret):
                    continue
                    
                # Cache successful retrieval
                self.cache.set(cache_key, secret)
                
                # Audit access
                await self._audit_secret_access(
                    secret_name,
                    provider.name,
                    context
                )
                
                return secret
                
            except ProviderException as e:
                self.logger.warning(
                    f"Provider {provider.name} failed",
                    error=str(e)
                )
                continue
                
        raise SecretsException(f"Failed to retrieve secret: {secret_name}")
```

---

## 2. Authentifizierungssystem

### 2.1 Authentik Integration (KEINE LOKALE AUTH!)

#### Anforderungen:
- **Authentik als Auth Provider**: KEINE lokale Authentifizierung implementieren
- **Passwordless Only**: Ausschließlich Device-basierte Authentifizierung
- **Token Exchange**: Authentik Tokens zu internen JWTs
- **Session Sync**: Bidirektionale Session-Validierung mit Authentik

#### Detaillierte Implementierung:

```python
# src/auth/authentik_client.py
from typing import Optional, Dict, Any
import httpx
from jose import jwt

class AuthentikClient:
    """
    Client für Authentik Integration - KEINE LOKALE AUTH!
    """
    
    def __init__(self, config: AuthentikConfig):
        self.base_url = config.base_url
        self.client = httpx.AsyncClient()
        # KEINE Passwort-bezogenen Felder!
        
    async def initiate_device_auth(
        self,
        tenant_id: str,
        device_info: DeviceInfo
    ) -> DeviceAuthChallenge:
        """
        Initiiert Device-basierte Authentifizierung.
        KEINE PASSWÖRTER!
        """
        tenant_config = await self._get_tenant_config(tenant_id)
        
        # Nur Device-basierte Auth-Methoden
        auth_methods = {
            "webauthn": {
                "enabled": True,
                "user_verification": "required",
                "resident_key": "required"
            },
            "device_certificate": {
                "enabled": tenant_config.allow_certificates,
                "ca_certificates": tenant_config.ca_certs
            },
            "passkey": {
                "enabled": True,
                "platforms": ["windows", "apple", "android"]
            }
        }
        
        # EXPLIZIT DEAKTIVIERT:
        # - password
        # - otp (außer als Backup)
        # - sms
        # - email (nur magic links)
        
        response = await self.client.post(
            f"{self.base_url}/api/v3/flows/executor/{tenant_config.flow_slug}/",
            json={
                "device_info": device_info.dict(),
                "auth_methods": auth_methods,
                "challenge_type": "device_only"  # WICHTIG!
            }
        )
        
        return DeviceAuthChallenge.parse_obj(response.json())
        
    async def complete_device_auth(
        self,
        challenge_id: str,
        device_response: DeviceAuthResponse
    ) -> AuthenticationResult:
        """
        Schließt Device-Authentifizierung ab.
        """
        # Validierung dass KEIN Passwort enthalten ist
        if hasattr(device_response, 'password') or 'password' in device_response.__dict__:
            raise SecurityError("Password authentication is forbidden!")
            
        response = await self.client.post(
            f"{self.base_url}/api/v3/flows/executor/challenge/{challenge_id}/",
            json={
                "response_type": device_response.type,  # webauthn, certificate, etc.
                "response_data": device_response.data
            }
        )
        
        if response.status_code == 200:
            return AuthenticationResult.parse_obj(response.json())
        else:
            raise AuthenticationError("Device authentication failed")
```

### 2.2 Device Authentication (PFLICHT!)

#### Anforderungen:
- **WebAuthn/FIDO2**: Primäre Authentifizierungsmethode
- **Passkeys**: Platform Authenticators (Windows Hello, Touch ID, Face ID)
- **Device Certificates**: Für managed devices
- **KEINE PASSWÖRTER**: Auch nicht als Fallback!

#### Implementierung:

```python
# src/auth/device/manager.py
from webauthn import generate_authentication_options, verify_authentication_response
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class DeviceAuthManager:
    """
    Verwaltung von Device-basierter Authentifizierung.
    KEINE PASSWÖRTER!
    """
    
    def __init__(self):
        # NUR Device-basierte Provider!
        self.providers = {
            "webauthn": WebAuthnProvider(),
            "passkey": PasskeyProvider(),
            "device_cert": DeviceCertificateProvider(),
            "platform": PlatformAuthenticatorProvider()  # Windows Hello, Touch ID
        }
        # EXPLIZIT KEINE: password, sms, email-password, otp
        
    async def enroll_device(
        self,
        user_id: str,
        device_type: str,
        device_info: DeviceInfo
    ) -> DeviceEnrollmentResponse:
        """
        Registriert ein neues Device für passwordlose Auth.
        """
        # Validierung: NUR Device-basierte Typen!
        if device_type not in self.providers:
            raise InvalidDeviceTypeError(
                f"Only device-based auth allowed: {list(self.providers.keys())}"
            )
            
        provider = self.providers[device_type]
        
        # Generate device-specific challenge
        if device_type == "webauthn":
            challenge = await provider.generate_registration_options(
                user_id=user_id,
                user_name=device_info.user_email,
                user_display_name=device_info.user_display_name,
                authenticator_selection={
                    "authenticator_attachment": "platform",
                    "user_verification": "required",
                    "resident_key": "required"  # Passkey support
                }
            )
        elif device_type == "device_cert":
            challenge = await provider.generate_csr_challenge(
                device_id=device_info.device_id,
                device_name=device_info.device_name
            )
        else:
            challenge = await provider.generate_challenge(device_info)
            
        return DeviceEnrollmentResponse(
            device_type=device_type,
            challenge=challenge,
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        
    async def verify_device(
        self,
        user_id: str,
        device_type: str,
        verification_data: dict
    ) -> DeviceVerificationResult:
        """
        Verifiziert ein Device für passwordlose Auth.
        """
        # SICHERHEITSCHECK: Keine Passwörter!
        if 'password' in verification_data:
            raise SecurityError("Password authentication is forbidden!")
            
        # Get user's enrolled devices
        devices = await self._get_user_devices(user_id)
        device = next((d for d in devices if d.type == device_type), None)
        
        if not device:
            raise DeviceNotEnrolledException(device_type)
            
        # Device trust check
        if not await self._verify_device_trust(device):
            raise DeviceNotTrustedException(
                "Device trust verification failed"
            )
            
        # Verify with provider
        provider = self.providers[device_type]
        
        if device_type == "webauthn":
            result = await provider.verify_authentication(
                credential_id=verification_data['credential_id'],
                client_data_json=verification_data['client_data_json'],
                authenticator_data=verification_data['authenticator_data'],
                signature=verification_data['signature'],
                user_handle=verification_data.get('user_handle')
            )
        elif device_type == "device_cert":
            result = await provider.verify_certificate(
                certificate=verification_data['certificate'],
                signature=verification_data['signature'],
                challenge=verification_data['challenge']
            )
        else:
            result = await provider.verify(device, verification_data)
            
        # Update device metadata
        if result.success:
            await self._update_device_last_used(device)
            
        # Audit device authentication
        await self._audit_device_auth(
            user_id=user_id,
            device=device,
            result=result
        )
        
        return result
```

### 2.3 Session Management

#### Anforderungen:
- **Secure Sessions**: Sichere Session-Verwaltung
- **Session Fixation Prevention**: Schutz vor Session-Übernahme
- **Concurrent Session Control**: Kontrolle paralleler Sessions

#### Implementierung:

```python
# src/auth/sessions/manager.py
import redis
from typing import List, Optional
import json

class SessionManager:
    """
    Sichere Session-Verwaltung mit Redis-Backend.
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.encryption_key = self._load_session_key()
        
    async def create_session(
        self,
        user: User,
        device_info: DeviceInfo,
        auth_method: str
    ) -> Session:
        """
        Erstellt eine neue sichere Session.
        """
        # Generate cryptographically secure session ID
        session_id = secrets.token_urlsafe(32)
        
        # Create session object
        session = Session(
            id=session_id,
            user_id=user.id,
            device_fingerprint=device_info.fingerprint,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
            auth_method=auth_method,
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        
        # Check concurrent session limits
        await self._enforce_session_limits(user)
        
        # Encrypt and store session
        encrypted_session = self._encrypt_session(session)
        await self.redis.setex(
            f"session:{session_id}",
            int(session.expires_at.timestamp() - datetime.utcnow().timestamp()),
            encrypted_session
        )
        
        # Add to user's session list
        await self.redis.sadd(f"user_sessions:{user.id}", session_id)
        
        # Audit session creation
        await log_audit_event(
            event_type=AuditEventType.SESSION_CREATED,
            user_id=user.id,
            details={
                "session_id": session_id,
                "auth_method": auth_method,
                "device_fingerprint": device_info.fingerprint
            }
        )
        
        return session
        
    async def validate_session(
        self,
        session_id: str,
        request_info: RequestInfo
    ) -> Optional[Session]:
        """
        Validiert und aktualisiert eine Session.
        """
        # Get encrypted session
        encrypted_session = await self.redis.get(f"session:{session_id}")
        if not encrypted_session:
            return None
            
        # Decrypt session
        session = self._decrypt_session(encrypted_session)
        
        # Validate session hasn't expired
        if session.expires_at < datetime.utcnow():
            await self.invalidate_session(session_id)
            return None
            
        # Validate device fingerprint
        if not self._validate_device_fingerprint(
            session.device_fingerprint,
            request_info.device_fingerprint
        ):
            # Possible session hijacking attempt
            await self._handle_suspicious_activity(session, request_info)
            return None
            
        # Update last activity
        session.last_activity = datetime.utcnow()
        
        # Extend session if approaching expiry
        if (session.expires_at - datetime.utcnow()).total_seconds() < 3600:
            session.expires_at = datetime.utcnow() + timedelta(hours=24)
            
        # Re-encrypt and update
        encrypted_session = self._encrypt_session(session)
        await self.redis.setex(
            f"session:{session_id}",
            int(session.expires_at.timestamp() - datetime.utcnow().timestamp()),
            encrypted_session
        )
        
        return session
```

---

## 3. Multi-Tenant-Architektur

### 3.1 Tenant Isolation

#### Anforderungen:
- **Vollständige Datenisolation**: Keine Datenlecks zwischen Tenants
- **Performance Isolation**: Ein Tenant kann andere nicht beeinträchtigen
- **Konfigurationsisolation**: Tenant-spezifische Einstellungen

#### Implementierung:

```python
# src/core/multitenancy/isolation.py
from contextvars import ContextVar
from sqlalchemy import event
from sqlalchemy.orm import Session

# Thread-safe tenant context
_tenant_context: ContextVar[Optional[str]] = ContextVar('tenant_context', default=None)

class TenantIsolationManager:
    """
    Verwaltet Tenant-Isolation auf allen Ebenen.
    """
    
    def __init__(self):
        self.tenant_resolver = TenantResolver()
        self.permission_checker = TenantPermissionChecker()
        
    async def set_tenant_context(
        self,
        request: Request,
        user: Optional[User] = None
    ) -> str:
        """
        Setzt den Tenant-Kontext für die aktuelle Anfrage.
        """
        # Resolve tenant from multiple sources
        tenant_id = await self.tenant_resolver.resolve(
            headers=request.headers,
            host=request.url.hostname,
            path=request.url.path,
            user=user
        )
        
        if not tenant_id:
            raise TenantNotFoundError()
            
        # Validate tenant exists and is active
        tenant = await self._get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            raise TenantInactiveError()
            
        # Check user has access to tenant
        if user and not await self.permission_checker.user_has_tenant_access(
            user=user,
            tenant=tenant
        ):
            raise TenantAccessDeniedError()
            
        # Set context
        _tenant_context.set(tenant_id)
        
        # Configure tenant-specific settings
        await self._configure_tenant_settings(tenant)
        
        return tenant_id
        
    def apply_tenant_filter(self, query):
        """
        Automatischer Tenant-Filter für alle Queries.
        """
        tenant_id = _tenant_context.get()
        if not tenant_id:
            raise TenantContextNotSetError()
            
        # Add tenant filter to query
        if hasattr(query.column_descriptions[0]['type'], 'tenant_id'):
            query = query.filter_by(tenant_id=tenant_id)
            
        return query
```

### 3.2 Tenant-Specific Configuration

#### Implementierung:

```python
# src/core/multitenancy/config.py
class TenantConfigManager:
    """
    Verwaltet tenant-spezifische Konfigurationen.
    """
    
    def __init__(self):
        self.cache = TenantConfigCache()
        self.validators = ConfigValidators()
        
    async def get_config(
        self,
        tenant_id: str,
        config_key: str,
        default: Any = None
    ) -> Any:
        """
        Holt tenant-spezifische Konfiguration mit Fallback.
        """
        # Check cache
        cache_key = f"{tenant_id}:{config_key}"
        if cached := self.cache.get(cache_key):
            return cached
            
        # Load from database
        config = await self._load_config(tenant_id, config_key)
        
        # Fall back to default
        if config is None:
            config = default or self._get_system_default(config_key)
            
        # Validate configuration
        if not self.validators.validate(config_key, config):
            raise InvalidConfigurationError(
                f"Invalid configuration for {config_key}"
            )
            
        # Cache result
        self.cache.set(cache_key, config, ttl=300)
        
        return config
        
    async def update_config(
        self,
        tenant_id: str,
        config_key: str,
        value: Any,
        updated_by: str
    ) -> None:
        """
        Aktualisiert tenant-spezifische Konfiguration.
        """
        # Validate permission
        if not await self._can_update_config(tenant_id, config_key, updated_by):
            raise PermissionDeniedError()
            
        # Validate new value
        if not self.validators.validate(config_key, value):
            raise InvalidConfigurationError()
            
        # Store with audit trail
        await self._store_config(
            tenant_id=tenant_id,
            config_key=config_key,
            value=value,
            updated_by=updated_by,
            updated_at=datetime.utcnow()
        )
        
        # Invalidate cache
        self.cache.invalidate(f"{tenant_id}:{config_key}")
        
        # Notify configuration change
        await self._notify_config_change(tenant_id, config_key, value)
```

---

## 4. API-Sicherheit

### 4.1 Rate Limiting & Throttling

#### Anforderungen:
- **Flexible Rate Limits**: Verschiedene Limits für verschiedene Endpoints
- **Tenant-basierte Limits**: Fair Use zwischen Tenants
- **DDoS-Schutz**: Automatische Erkennung und Mitigation

#### Implementierung:

```python
# src/api/security/rate_limiting.py
from collections import defaultdict
import time
import asyncio

class RateLimiter:
    """
    Fortgeschrittenes Rate Limiting mit mehreren Strategien.
    """
    
    def __init__(self):
        self.strategies = {
            "token_bucket": TokenBucketStrategy(),
            "sliding_window": SlidingWindowStrategy(),
            "fixed_window": FixedWindowStrategy(),
            "adaptive": AdaptiveRateLimitStrategy()
        }
        
    async def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        tenant_id: Optional[str] = None
    ) -> RateLimitResult:
        """
        Prüft Rate Limits mit mehreren Strategien.
        """
        # Get applicable limits
        limits = await self._get_applicable_limits(
            identifier=identifier,
            endpoint=endpoint,
            tenant_id=tenant_id
        )
        
        results = []
        for limit in limits:
            strategy = self.strategies[limit.strategy]
            result = await strategy.check(
                identifier=identifier,
                limit=limit
            )
            results.append(result)
            
        # Return most restrictive result
        return self._combine_results(results)
        
class AdaptiveRateLimitStrategy:
    """
    Adaptive Rate Limiting basierend auf Systemlast.
    """
    
    def __init__(self):
        self.load_monitor = SystemLoadMonitor()
        self.history_analyzer = RequestHistoryAnalyzer()
        
    async def check(
        self,
        identifier: str,
        limit: RateLimit
    ) -> RateLimitResult:
        """
        Adaptives Rate Limiting.
        """
        # Get current system load
        system_load = await self.load_monitor.get_current_load()
        
        # Get request history
        history = await self.history_analyzer.get_history(identifier)
        
        # Calculate adaptive limit
        adaptive_limit = self._calculate_adaptive_limit(
            base_limit=limit.requests_per_period,
            system_load=system_load,
            request_history=history
        )
        
        # Check against adaptive limit
        current_count = await self._get_current_count(identifier)
        
        if current_count >= adaptive_limit:
            # Calculate backoff
            backoff = self._calculate_backoff(
                current_count=current_count,
                limit=adaptive_limit,
                history=history
            )
            
            return RateLimitResult(
                allowed=False,
                limit=adaptive_limit,
                remaining=0,
                reset_at=time.time() + backoff,
                retry_after=backoff
            )
            
        return RateLimitResult(
            allowed=True,
            limit=adaptive_limit,
            remaining=adaptive_limit - current_count,
            reset_at=time.time() + limit.period_seconds
        )
```

### 4.2 API Key Management

#### Anforderungen:
- **Sichere Key-Generierung**: Kryptographisch sichere Keys
- **Key Rotation**: Automatische und manuelle Rotation
- **Granulare Berechtigungen**: Scope-basierte Zugriffskontrolle

#### Implementierung:

```python
# src/api/security/api_keys.py
import secrets
import hashlib
from typing import List, Optional

class APIKeyManager:
    """
    Verwaltung von API Keys mit Best Practices.
    """
    
    KEY_PREFIX = "sk_"  # Secret key prefix
    KEY_LENGTH = 32     # 256 bits of entropy
    
    def __init__(self):
        self.hasher = APIKeyHasher()
        self.validator = APIKeyValidator()
        self.rotation_scheduler = KeyRotationScheduler()
        
    async def create_api_key(
        self,
        tenant_id: str,
        name: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
        created_by: str = None
    ) -> APIKeyCreationResult:
        """
        Erstellt einen neuen API Key.
        """
        # Generate cryptographically secure key
        key_material = secrets.token_bytes(self.KEY_LENGTH)
        key_string = f"{self.KEY_PREFIX}{base64.urlsafe_b64encode(key_material).decode('utf-8').rstrip('=')}"
        
        # Hash key for storage
        key_hash = self.hasher.hash(key_string)
        
        # Generate key ID
        key_id = f"key_{secrets.token_urlsafe(16)}"
        
        # Create key record
        api_key = APIKey(
            id=key_id,
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_string[:12],  # Store prefix for identification
            scopes=scopes,
            created_at=datetime.utcnow(),
            created_by=created_by,
            expires_at=expires_at,
            last_used_at=None,
            is_active=True
        )
        
        # Save to database
        await self._save_api_key(api_key)
        
        # Schedule rotation if configured
        if expires_at:
            await self.rotation_scheduler.schedule_rotation(
                key_id=key_id,
                rotation_date=expires_at - timedelta(days=7)  # 7 days before expiry
            )
            
        # Audit key creation
        await log_audit_event(
            event_type=AuditEventType.API_KEY_CREATED,
            user_id=created_by,
            details={
                "key_id": key_id,
                "tenant_id": tenant_id,
                "scopes": scopes,
                "expires_at": expires_at.isoformat() if expires_at else None
            }
        )
        
        return APIKeyCreationResult(
            key_id=key_id,
            api_key=key_string,  # Only returned once
            expires_at=expires_at
        )
        
    async def validate_api_key(
        self,
        api_key: str,
        required_scopes: List[str] = None
    ) -> Optional[APIKeyContext]:
        """
        Validiert einen API Key und prüft Berechtigungen.
        """
        # Basic format validation
        if not self.validator.validate_format(api_key):
            return None
            
        # Extract key prefix for lookup
        key_prefix = api_key[:12]
        
        # Find potential matches by prefix
        potential_keys = await self._find_keys_by_prefix(key_prefix)
        
        # Verify against hashes
        for key_record in potential_keys:
            if self.hasher.verify(api_key, key_record.key_hash):
                # Check if key is active
                if not key_record.is_active:
                    await self._audit_invalid_key_use(
                        key_id=key_record.id,
                        reason="inactive"
                    )
                    return None
                    
                # Check expiration
                if key_record.expires_at and key_record.expires_at < datetime.utcnow():
                    await self._audit_invalid_key_use(
                        key_id=key_record.id,
                        reason="expired"
                    )
                    return None
                    
                # Check scopes
                if required_scopes and not self._check_scopes(
                    key_record.scopes,
                    required_scopes
                ):
                    await self._audit_invalid_key_use(
                        key_id=key_record.id,
                        reason="insufficient_scopes"
                    )
                    return None
                    
                # Update last used
                await self._update_last_used(key_record.id)
                
                return APIKeyContext(
                    key_id=key_record.id,
                    tenant_id=key_record.tenant_id,
                    scopes=key_record.scopes,
                    metadata=key_record.metadata
                )
                
        # No valid key found
        await self._audit_invalid_key_use(
            key_prefix=key_prefix,
            reason="not_found"
        )
        return None
```

---

## 5. Datenbank-Sicherheit

### 5.1 Verschlüsselung

#### Anforderungen:
- **Encryption at Rest**: Alle sensitiven Daten verschlüsselt
- **Field-Level Encryption**: Granulare Verschlüsselung
- **Key Rotation**: Regelmäßige Schlüsselrotation

#### Implementierung:

```python
# src/database/security/encryption.py
from sqlalchemy import TypeDecorator, String
from cryptography.fernet import Fernet

class EncryptedField(TypeDecorator):
    """
    SQLAlchemy Type für verschlüsselte Felder.
    """
    impl = String
    cache_ok = True
    
    def __init__(self, key_name: str = "default", *args, **kwargs):
        self.key_name = key_name
        super().__init__(*args, **kwargs)
        
    def process_bind_param(self, value, dialect):
        """
        Verschlüsselt Werte vor dem Speichern.
        """
        if value is None:
            return None
            
        # Get encryption key
        key = self._get_encryption_key()
        fernet = Fernet(key)
        
        # Encrypt value
        encrypted = fernet.encrypt(value.encode('utf-8'))
        
        # Add key version for rotation support
        return f"{self.key_name}:v1:{encrypted.decode('utf-8')}"
        
    def process_result_value(self, value, dialect):
        """
        Entschlüsselt Werte nach dem Laden.
        """
        if value is None:
            return None
            
        # Parse encrypted value
        parts = value.split(':', 2)
        if len(parts) != 3:
            raise EncryptionError("Invalid encrypted value format")
            
        key_name, version, encrypted = parts
        
        # Get appropriate key version
        key = self._get_encryption_key(key_name, version)
        fernet = Fernet(key)
        
        # Decrypt value
        try:
            decrypted = fernet.decrypt(encrypted.encode('utf-8'))
            return decrypted.decode('utf-8')
        except Exception as e:
            raise EncryptionError(f"Failed to decrypt value: {e}")

class DatabaseEncryptionManager:
    """
    Verwaltet Datenbank-Verschlüsselung und Key Rotation.
    """
    
    def __init__(self):
        self.key_manager = DatabaseKeyManager()
        self.rotation_coordinator = RotationCoordinator()
        
    async def rotate_encryption_keys(
        self,
        table_name: str,
        column_name: str,
        batch_size: int = 1000
    ) -> RotationResult:
        """
        Rotiert Verschlüsselungsschlüssel für eine Spalte.
        """
        # Generate new key version
        new_key = await self.key_manager.generate_new_key()
        
        # Create rotation job
        job = RotationJob(
            table_name=table_name,
            column_name=column_name,
            old_key_version="v1",
            new_key_version="v2",
            batch_size=batch_size
        )
        
        # Execute rotation
        async with self.rotation_coordinator.coordinate(job) as coordinator:
            total_rows = await coordinator.count_rows()
            processed = 0
            
            while processed < total_rows:
                # Read batch with old key
                batch = await coordinator.read_batch(
                    offset=processed,
                    limit=batch_size
                )
                
                # Re-encrypt with new key
                for row in batch:
                    decrypted = self._decrypt_with_key(
                        row[column_name],
                        self.key_manager.get_key("v1")
                    )
                    
                    encrypted = self._encrypt_with_key(
                        decrypted,
                        new_key
                    )
                    
                    await coordinator.update_row(
                        row_id=row['id'],
                        column_name=column_name,
                        new_value=encrypted
                    )
                    
                processed += len(batch)
                
                # Progress callback
                await coordinator.report_progress(
                    processed=processed,
                    total=total_rows
                )
                
        return RotationResult(
            rows_processed=processed,
            duration=coordinator.elapsed_time,
            new_key_version="v2"
        )
```

### 5.2 Query Security

#### Anforderungen:
- **SQL Injection Prevention**: Parametrisierte Queries
- **Query Monitoring**: Überwachung verdächtiger Queries
- **Access Control**: Row-Level Security

#### Implementierung:

```python
# src/database/security/query_security.py
class SecureQueryBuilder:
    """
    Sicherer Query Builder mit Injection-Schutz.
    """
    
    def __init__(self):
        self.query_validator = QueryValidator()
        self.parameter_sanitizer = ParameterSanitizer()
        self.query_logger = QueryAuditLogger()
        
    def build_select_query(
        self,
        table: str,
        columns: List[str],
        conditions: Dict[str, Any],
        tenant_id: str
    ) -> Query:
        """
        Baut eine sichere SELECT Query.
        """
        # Validate table name
        if not self.query_validator.is_valid_table_name(table):
            raise InvalidTableNameError(table)
            
        # Validate column names
        for column in columns:
            if not self.query_validator.is_valid_column_name(column):
                raise InvalidColumnNameError(column)
                
        # Build query with automatic tenant filter
        query = select([
            column(c) for c in columns
        ]).select_from(
            table(table)
        ).where(
            column('tenant_id') == bindparam('tenant_id')
        )
        
        # Add conditions safely
        for col, value in conditions.items():
            if not self.query_validator.is_valid_column_name(col):
                raise InvalidColumnNameError(col)
                
            # Sanitize value
            sanitized_value = self.parameter_sanitizer.sanitize(value)
            
            query = query.where(
                column(col) == bindparam(f'param_{col}')
            )
            
        # Log query for audit
        await self.query_logger.log_query(
            query_type="SELECT",
            table=table,
            tenant_id=tenant_id,
            conditions=conditions
        )
        
        return query

class RowLevelSecurity:
    """
    Implementiert Row-Level Security für Mandantenfähigkeit.
    """
    
    def __init__(self):
        self.policy_manager = SecurityPolicyManager()
        
    def apply_rls_policy(self, query, user_context: UserContext):
        """
        Wendet RLS-Policies auf eine Query an.
        """
        # Get applicable policies
        policies = self.policy_manager.get_policies_for_user(user_context)
        
        for policy in policies:
            if policy.applies_to_table(query.table):
                # Add policy conditions
                query = query.where(
                    policy.get_filter_condition(user_context)
                )
                
        return query
```

---

## 6. Infrastruktur-Sicherheit

### 6.1 Container Security

#### Anforderungen:
- **Minimal Base Images**: Reduzierte Angriffsfläche
- **Non-Root Container**: Keine privilegierten Container
- **Security Scanning**: Automatisches Vulnerability Scanning

#### Implementierung:

```dockerfile
# Dockerfile
# Use distroless base image for minimal attack surface
FROM python:3.12-slim AS builder

# Install dependencies in builder stage
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage with distroless image
FROM gcr.io/distroless/python3-debian12

# Copy only necessary files
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /app /app

# Run as non-root user
USER nonroot:nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD ["/usr/bin/python3", "-c", "import requests; requests.get('http://localhost:8000/health')"]

# Security labels
LABEL security.scan="enabled" \
      security.non-root="true" \
      security.read-only-root="true"

# Read-only root filesystem
# Volumes for writable data
VOLUME ["/tmp", "/var/log/app"]

# Run application
ENTRYPOINT ["python3", "-m", "uvicorn", "src.main:app"]
```

### 6.2 Network Security

#### Anforderungen:
- **TLS Everywhere**: Verschlüsselte Kommunikation
- **Network Policies**: Kubernetes NetworkPolicies
- **Service Mesh**: Istio/Linkerd für Zero-Trust Networking

#### Kubernetes Network Policy:

```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-network-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: nai-backend
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow traffic from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - protocol: TCP
      port: 8000
      
  # Allow traffic from frontend pods
  - from:
    - podSelector:
        matchLabels:
          app: nai-frontend
    ports:
    - protocol: TCP
      port: 8000
      
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
      
  # Allow database access
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432
      
  # Allow Redis access
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
      
  # Allow external HTTPS for OAuth providers
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32  # Block metadata service
        - 10.0.0.0/8          # Block internal networks
        - 172.16.0.0/12
        - 192.168.0.0/16
    ports:
    - protocol: TCP
      port: 443
```

---

## 7. Compliance & Audit

### 7.1 Audit Logging

#### Anforderungen:
- **Vollständiges Audit Trail**: Alle sicherheitsrelevanten Events
- **Tamper-Proof Logs**: Unveränderliche Audit Logs
- **Real-time Alerting**: Sofortige Benachrichtigung bei kritischen Events

#### Implementierung:

```python
# src/audit/comprehensive_audit.py
from typing import Dict, Any
import hashlib
import json

class ComprehensiveAuditLogger:
    """
    Umfassendes Audit Logging für Compliance.
    """
    
    def __init__(self):
        self.event_classifier = SecurityEventClassifier()
        self.integrity_manager = LogIntegrityManager()
        self.alert_manager = SecurityAlertManager()
        
    async def log_security_event(
        self,
        event: SecurityEvent
    ) -> None:
        """
        Loggt ein Sicherheitsevent mit vollständigem Kontext.
        """
        # Classify event severity
        severity = self.event_classifier.classify(event)
        
        # Enrich with context
        enriched_event = await self._enrich_event(event)
        
        # Create immutable log entry
        log_entry = AuditLogEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            event_type=event.type,
            severity=severity,
            actor=enriched_event.actor,
            resource=enriched_event.resource,
            action=enriched_event.action,
            result=enriched_event.result,
            details=enriched_event.details,
            context={
                "ip_address": enriched_event.ip_address,
                "user_agent": enriched_event.user_agent,
                "session_id": enriched_event.session_id,
                "request_id": enriched_event.request_id,
                "tenant_id": enriched_event.tenant_id
            }
        )
        
        # Calculate integrity hash
        log_entry.integrity_hash = self.integrity_manager.calculate_hash(log_entry)
        
        # Chain with previous log hash
        previous_hash = await self._get_previous_hash()
        log_entry.previous_hash = previous_hash
        log_entry.chain_hash = self.integrity_manager.calculate_chain_hash(
            log_entry,
            previous_hash
        )
        
        # Store in immutable storage
        await self._store_immutable(log_entry)
        
        # Check if alerting required
        if severity >= SecuritySeverity.HIGH:
            await self.alert_manager.send_alert(
                event=enriched_event,
                severity=severity
            )
            
        # Real-time streaming for SIEM
        await self._stream_to_siem(log_entry)
        
class LogIntegrityManager:
    """
    Sichert die Integrität von Audit Logs.
    """
    
    def __init__(self):
        self.hash_algorithm = hashlib.sha3_256
        
    def calculate_hash(self, log_entry: AuditLogEntry) -> str:
        """
        Berechnet kryptographischen Hash für Log-Eintrag.
        """
        # Create canonical representation
        canonical = json.dumps({
            "id": log_entry.id,
            "timestamp": log_entry.timestamp.isoformat(),
            "event_type": log_entry.event_type,
            "severity": log_entry.severity,
            "actor": log_entry.actor,
            "resource": log_entry.resource,
            "action": log_entry.action,
            "result": log_entry.result,
            "details": log_entry.details,
            "context": log_entry.context
        }, sort_keys=True)
        
        # Calculate hash
        return self.hash_algorithm(canonical.encode()).hexdigest()
        
    def verify_integrity(
        self,
        log_entry: AuditLogEntry,
        expected_hash: str
    ) -> bool:
        """
        Verifiziert die Integrität eines Log-Eintrags.
        """
        calculated_hash = self.calculate_hash(log_entry)
        return hmac.compare_digest(calculated_hash, expected_hash)
```

### 7.2 Compliance Reporting

#### Implementierung:

```python
# src/compliance/reporting.py
class ComplianceReporter:
    """
    Generiert Compliance-Reports für verschiedene Standards.
    """
    
    def __init__(self):
        self.report_generators = {
            "gdpr": GDPRReportGenerator(),
            "sox": SOXReportGenerator(),
            "hipaa": HIPAAReportGenerator(),
            "pci_dss": PCIDSSReportGenerator()
        }
        # WICHTIG: Passwordless Auth Compliance Check!
        self.password_checker = PasswordlessComplianceChecker()
        
    async def generate_compliance_report(
        self,
        standard: str,
        start_date: datetime,
        end_date: datetime,
        tenant_id: Optional[str] = None
    ) -> ComplianceReport:
        """
        Generiert einen Compliance-Report.
        """
        generator = self.report_generators.get(standard)
        if not generator:
            raise UnsupportedStandardError(standard)
            
        # Collect audit data
        audit_data = await self._collect_audit_data(
            start_date=start_date,
            end_date=end_date,
            tenant_id=tenant_id
        )
        
        # Generate report
        report = await generator.generate(
            audit_data=audit_data,
            period_start=start_date,
            period_end=end_date
        )
        
        # Sign report for integrity
        report.signature = await self._sign_report(report)
        
        # Store report
        await self._store_report(report)
        
        return report
```

---

## 8. Entwicklungsphasen

### Phase 1: Security Foundation (4 Wochen)
1. **Woche 1-2**: Zero-Trust Architektur und Crypto Management
2. **Woche 3-4**: Secrets Management und Audit Logging

### Phase 2: Authentik Integration & Device Auth (6 Wochen)
1. **Woche 1-2**: Authentik Setup und Multi-Tenant Konfiguration
2. **Woche 3-4**: WebAuthn/Passkey Implementation (KEINE PASSWÖRTER!)
3. **Woche 5-6**: Token Exchange Service und Session Sync

### Phase 3: Multi-Tenancy (4 Wochen)
1. **Woche 1-2**: Tenant Isolation
2. **Woche 3-4**: Tenant-specific Configuration

### Phase 4: API Security (3 Wochen)
1. **Woche 1**: Rate Limiting und DDoS Protection
2. **Woche 2-3**: API Key Management

### Phase 5: Database Security (3 Wochen)
1. **Woche 1-2**: Encryption at Rest
2. **Woche 3**: Query Security und RLS

### Phase 6: Infrastructure Security (2 Wochen)
1. **Woche 1**: Container Security
2. **Woche 2**: Network Policies

### Phase 7: Compliance & Testing (4 Wochen)
1. **Woche 1-2**: Compliance Reporting
2. **Woche 3-4**: Security Testing und Penetration Testing

---

## 9. Technische Spezifikationen

### Dependencies
```toml
[tool.poetry.dependencies]
python = "^3.12"
fastapi = "^0.109.0"
uvicorn = {extras = ["standard"], version = "^0.27.0"}
structlog = "^24.1.0"
pydantic = "^2.5.0"
pydantic-settings = "^2.1.0"
sqlalchemy = "^2.0.0"
alembic = "^1.13.0"
redis = "^5.0.0"
authlib = "^1.3.0"
cryptography = "^42.0.0"
pyotp = "^2.9.0"
webauthn = "^2.0.0"
python-jose = {extras = ["cryptography"], version = "^3.3.0"}
passlib = {extras = ["bcrypt"], version = "^1.7.4"}
python-multipart = "^0.0.6"
httpx = "^0.26.0"
celery = "^5.3.0"
prometheus-client = "^0.19.0"
opentelemetry-api = "^1.22.0"
opentelemetry-sdk = "^1.22.0"
opentelemetry-instrumentation-fastapi = "^0.43b0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
pytest-asyncio = "^0.23.0"
pytest-cov = "^4.1.0"
black = "^24.1.0"
ruff = "^0.1.0"
mypy = "^1.8.0"
bandit = "^1.7.0"
safety = "^3.0.0"
```

### Umgebungsvariablen
```bash
# Security
ENCRYPTION_KEY=base64_encoded_32_byte_key
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Authentik Integration
AUTHENTIK_BASE_URL=https://auth.example.com
AUTHENTIK_CLIENT_ID=nai-backend
AUTHENTIK_CLIENT_SECRET=your-client-secret
AUTHENTIK_FLOW_SLUG=passwordless-authentication

# Device Authentication
WEBAUTHN_RP_ID=example.com
WEBAUTHN_RP_NAME=nAI Platform
WEBAUTHN_USER_VERIFICATION=required
DEVICE_AUTH_REQUIRED=true
PASSWORD_AUTH_ENABLED=false  # MUSS false sein!

# Session
SESSION_SECRET_KEY=your-session-secret
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=strict

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_LIMIT=100
RATE_LIMIT_DEFAULT_PERIOD=60

# Audit
AUDIT_LOG_RETENTION_DAYS=2555  # 7 Jahre
AUDIT_REAL_TIME_STREAMING=true
AUDIT_INTEGRITY_CHECK_ENABLED=true
```

---

## 10. Risikobewertung

### Kritische Risiken

1. **Insider Threats**
   - **Mitigation**: Least Privilege, Audit Logging, Anomaly Detection
   
2. **Supply Chain Attacks**
   - **Mitigation**: Dependency Scanning, SBOM, Vendoring kritischer Dependencies
   
3. **Zero-Day Exploits**
   - **Mitigation**: Defense in Depth, Rapid Patching Process, WAF
   
4. **Data Exfiltration**
   - **Mitigation**: DLP, Egress Monitoring, Encryption
   
5. **Credential Stuffing**
   - **Mitigation**: MFA, Account Lockout, Breach Detection

### Security KPIs

- **MTTD (Mean Time to Detect)**: < 1 Minute für kritische Events
- **MTTR (Mean Time to Respond)**: < 15 Minuten
- **Patch Compliance**: 100% innerhalb SLA
- **MFA Adoption**: > 95%
- **Security Training Completion**: 100%

---

## Zusammenfassung

Dieser umfassende Entwicklungsplan stellt sicher, dass das nAI Backend v5 höchsten Sicherheitsstandards entspricht. Die Implementierung folgt dem Prinzip "Security by Design" und berücksichtigt aktuelle Bedrohungen sowie zukünftige Anforderungen.

### ⚠️ KRITISCHE ARCHITEKTUR-ENTSCHEIDUNGEN:

1. **KEINE LOKALE AUTHENTIFIZIERUNG**: Alle Auth über Authentik
2. **NUR DEVICE-BASIERTE AUTH**: WebAuthn, Passkeys, Certificates
3. **KEINE PASSWÖRTER**: Weder in DB noch API
4. **AUTHENTIK ALS SINGLE SOURCE OF TRUTH**: Für alle Auth-Belange

Die geschätzte Gesamtdauer beträgt **26 Wochen** für die vollständige Implementierung aller Sicherheitsfeatures. Priorisierung kann basierend auf spezifischen Anforderungen erfolgen.

**Nächste Schritte:**
1. Review und Genehmigung des Plans
2. Authentik-Instanz aufsetzen
3. Start mit Phase 1: Security Foundation

---

**Dokument Version**: 1.0  
**Erstellt**: 2024-01-20  
**Klassifizierung**: VERTRAULICH